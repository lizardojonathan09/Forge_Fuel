import { serve } from 'https://deno.land/std@0.208.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import Stripe from 'https://esm.sh/stripe@14?target=deno'

const stripe = new Stripe(Deno.env.get('STRIPE_SECRET_KEY') ?? '', {
  apiVersion: '2023-10-16',
  httpClient: Stripe.createFetchHttpClient(),
})

const sb = createClient(
  Deno.env.get('SUPABASE_URL') ?? '',
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
)

// Matches pricing in index.html PACK_OPTIONS
const PER_CUP: Record<string, number> = {
  'full-3': 8.00, 'full-5': 7.50, 'full-7': 7.00,
  'half-5': 5.00, 'half-7': 4.50, 'half-9': 4.00,
}
const SUB_DISC = 0.10

serve(async (req) => {
  const sig  = req.headers.get('stripe-signature') ?? ''
  const body = await req.text()

  let event: Stripe.Event
  try {
    event = await stripe.webhooks.constructEventAsync(
      body, sig, Deno.env.get('STRIPE_WEBHOOK_SECRET') ?? ''
    )
  } catch (err) {
    console.error('Signature verification failed:', err.message)
    return new Response(`Webhook error: ${err.message}`, { status: 400 })
  }

  try {
    if (event.type === 'checkout.session.completed') {
      await handleCheckoutComplete(event.data.object as Stripe.Checkout.Session)
    } else if (event.type === 'invoice.payment_succeeded') {
      const inv = event.data.object as Stripe.Invoice
      // subscription_cycle = recurring renewal (first charge handled above)
      if (inv.billing_reason === 'subscription_cycle') {
        await handleRenewal(inv)
      }
    }
  } catch (err) {
    console.error('Handler error:', err)
    return new Response('Internal error', { status: 500 })
  }

  return new Response(JSON.stringify({ received: true }), {
    headers: { 'Content-Type': 'application/json' },
  })
})

// ── Checkout completed (one-time payment OR first subscription charge) ────
async function handleCheckoutComplete(session: Stripe.Checkout.Session) {
  const email  = session.customer_details?.email ?? ''
  const rawRef = session.client_reference_id ?? ''

  // Idempotency guard — Stripe can retry webhooks
  const { data: dup } = await sb.from('orders')
    .select('id').eq('stripe_session_id', session.id).maybeSingle()
  if (dup) return

  const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(rawRef)

  if (session.mode === 'subscription' && isUUID) {
    // ── Subscription started from dashboard ───────────────────────────────
    // client_reference_id is the Supabase user UUID
    const customerId = rawRef

    // Tag the Stripe subscription with the Supabase user ID so renewals
    // can look up subscription settings without hitting the checkout session
    if (session.subscription) {
      await stripe.subscriptions.update(session.subscription as string, {
        metadata: { supabase_customer_id: customerId },
      })
    }

    await insertSubOrder({ customerId, email, sessionId: session.id, amountTotal: session.amount_total })

  } else if (session.mode === 'payment') {
    // ── One-time purchase from index.html ─────────────────────────────────
    // client_reference_id is the encoded order string we built in handleCheckout()
    const ref    = decodeURIComponent(rawRef)
    const parsed = parseRef(ref)

    const { data: customer } = await sb.from('customers')
      .select('id').eq('email', email).maybeSingle()

    await sb.from('orders').insert({
      customer_id:       customer?.id ?? null,
      customer_email:    email,
      customer_name:     parsed.name ?? session.customer_details?.name ?? '',
      flavor:            parsed.flavor ?? '',
      portion:           parsed.portion ?? '',
      pack_size:         parsed.pack_size ?? null,
      order_type:        'one-time',
      total:             parsed.price ?? formatAmount(session.amount_total),
      delivery_date:     parsed.date ?? '',
      delivery_time:     parsed.time ?? '',
      referred_by:       parsed.ref ?? null,
      stripe_session_id: session.id,
    })
  }
}

// ── Recurring subscription renewal ───────────────────────────────────────
async function handleRenewal(invoice: Stripe.Invoice) {
  // Idempotency guard
  const { data: dup } = await sb.from('orders')
    .select('id').eq('stripe_invoice_id', invoice.id).maybeSingle()
  if (dup) return

  // Retrieve Stripe subscription to get the Supabase customer ID we stored
  const stripeSub = await stripe.subscriptions.retrieve(invoice.subscription as string)
  const customerId = stripeSub.metadata?.supabase_customer_id
  if (!customerId) {
    console.warn('No supabase_customer_id in subscription metadata, skipping')
    return
  }

  await insertSubOrder({
    customerId,
    email:       invoice.customer_email ?? '',
    invoiceId:   invoice.id,
    amountTotal: invoice.amount_paid,
  })
}

// ── Build and insert a subscription order from stored settings ────────────
async function insertSubOrder({ customerId, email, sessionId, invoiceId, amountTotal }: {
  customerId:   string
  email:        string
  sessionId?:   string
  invoiceId?:   string
  amountTotal?: number | null
}) {
  const [{ data: sub }, { data: cust }] = await Promise.all([
    sb.from('subscriptions').select('*').eq('customer_id', customerId).maybeSingle(),
    sb.from('customers').select('name,phone').eq('id', customerId).maybeSingle(),
  ])
  if (!sub) {
    console.warn('No subscription found for customer', customerId)
    return
  }

  const cups    = (sub.chocolate_cups ?? 0) + (sub.peanut_butter_cups ?? 0)
  const flavors: string[] = []
  if ((sub.chocolate_cups ?? 0) > 0)     flavors.push(`${sub.chocolate_cups} Chocolate`)
  if ((sub.peanut_butter_cups ?? 0) > 0) flavors.push(`${sub.peanut_butter_cups} Peanut Butter`)

  const basePerCup = PER_CUP[`${sub.portion}-${cups}`] ?? 7.50
  const total = amountTotal != null
    ? formatAmount(amountTotal)
    : '$' + (basePerCup * cups * (1 - SUB_DISC)).toFixed(2)

  await sb.from('orders').insert({
    customer_id:       customerId,
    customer_email:    email,
    customer_name:     cust?.name ?? '',
    customer_phone:    cust?.phone ?? null,
    flavor:            flavors.join(' + ') || 'Chocolate',
    portion:           sub.portion === 'half' ? 'Half Serving' : 'Full Serving',
    pack_size:         cups,
    order_type:        'subscribe',
    total,
    delivery_date:     sub.delivery_day  ?? '',
    delivery_time:     sub.delivery_time ?? '',
    referred_by:       null,
    stripe_session_id: sessionId ?? null,
    stripe_invoice_id: invoiceId ?? null,
  })
}

// ── Helpers ───────────────────────────────────────────────────────────────

// Parses the encoded client_reference_id string built in index.html
// Format: "5pack|one-time|flavor:5 Chocolate|portion:Full Serving|price:$33.75|..."
function parseRef(ref: string): Record<string, any> {
  const result: Record<string, any> = {}
  const packMatch = ref.match(/^(\d+)pack/)
  if (packMatch) result.pack_size = parseInt(packMatch[1])
  ref.split('|').forEach(part => {
    const idx = part.indexOf(':')
    if (idx > -1) result[part.slice(0, idx)] = part.slice(idx + 1)
  })
  return result
}

function formatAmount(cents?: number | null): string {
  return '$' + ((cents ?? 0) / 100).toFixed(2)
}
