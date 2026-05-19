import { serve } from 'https://deno.land/std@0.208.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

// No Stripe SDK — all Stripe calls use native fetch to avoid Deno compatibility issues

const sb = createClient(
  Deno.env.get('SUPABASE_URL') ?? '',
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
)

const PER_CUP: Record<string, number> = {
  'full-3': 8.00, 'full-5': 7.50, 'full-7': 7.00,
  'half-5': 5.00, 'half-7': 4.50, 'half-9': 4.00,
}
const SUB_DISC = 0.10

const STRIPE_PRICE_IDS: Record<string, string> = {
  'full-3': 'price_1TCsfnGvW9gqEv4EEirJkv9p',
  'full-5': 'price_1TCsfoGvW9gqEv4E9YpvdZKq',
  'full-7': 'price_1TCsfoGvW9gqEv4EudEUlFi3',
  'half-5': 'price_1TLoX0GvW9gqEv4ErxWDfHoF',
  'half-7': 'price_1TLoYlGvW9gqEv4E0eSQjBIh',
  'half-9': 'price_1TLoaMGvW9gqEv4EZKOSX9Ja',
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

// ── Stripe REST API helper ────────────────────────────────────────────────
async function stripeReq(path: string, method = 'GET', params?: URLSearchParams) {
  const res = await fetch(`https://api.stripe.com/v1${path}`, {
    method,
    headers: {
      'Authorization': `Bearer ${Deno.env.get('STRIPE_SECRET_KEY') ?? ''}`,
      'Content-Type':  'application/x-www-form-urlencoded',
    },
    body: params?.toString(),
  })
  return res.json()
}

// ── Stripe webhook signature verification (Web Crypto — no SDK) ───────────
async function verifyStripeSignature(body: string, sig: string, secret: string): Promise<boolean> {
  let timestamp = ''
  const signatures: string[] = []
  for (const part of sig.split(',')) {
    const idx = part.indexOf('=')
    const key = part.slice(0, idx)
    const val = part.slice(idx + 1)
    if (key === 't')  timestamp = val
    if (key === 'v1') signatures.push(val)
  }
  if (!timestamp || signatures.length === 0) return false

  // Reject events older than 5 minutes
  if (Math.abs(Date.now() / 1000 - parseInt(timestamp)) > 300) return false

  const signedPayload = `${timestamp}.${body}`
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const sigBytes = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(signedPayload))
  const computed  = Array.from(new Uint8Array(sigBytes)).map(b => b.toString(16).padStart(2, '0')).join('')
  return signatures.some(s => s === computed)
}

// ── Router ────────────────────────────────────────────────────────────────
serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS })

  try {
    const sig  = req.headers.get('stripe-signature')
    const auth = req.headers.get('authorization')

    if (sig)  return await handleWebhook(req, sig)
    if (auth) return await handleApiRequest(req, auth)

    return new Response('Bad request', { status: 400, headers: CORS })
  } catch (err) {
    console.error('Unhandled error:', err)
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500,
      headers: { ...CORS, 'Content-Type': 'application/json' },
    })
  }
})

// ── Stripe webhook ────────────────────────────────────────────────────────
async function handleWebhook(req: Request, sig: string) {
  const body   = await req.text()
  const secret = Deno.env.get('STRIPE_WEBHOOK_SECRET') ?? ''

  const valid = await verifyStripeSignature(body, sig, secret)
  if (!valid) {
    console.error('Webhook signature verification failed')
    return new Response('Webhook signature invalid', { status: 400 })
  }

  const event = JSON.parse(body)

  try {
    if (event.type === 'checkout.session.completed') {
      await handleCheckoutComplete(event.data.object)
    } else if (event.type === 'invoice.payment_succeeded') {
      if (event.data.object.billing_reason === 'subscription_cycle') {
        await handleRenewal(event.data.object)
      }
    }
  } catch (err) {
    console.error('Handler error:', err)
    return new Response('Internal error', { status: 500 })
  }

  return new Response(JSON.stringify({ received: true }), {
    headers: { 'Content-Type': 'application/json' },
  })
}

// ── API request from dashboard ────────────────────────────────────────────
async function handleApiRequest(req: Request, auth: string) {
  // Use service-role client to verify the user's JWT token
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : auth
  const { data, error } = await sb.auth.getUser(token)
  const user = data?.user
  if (error || !user) {
    console.error('Auth error:', error)
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401, headers: { ...CORS, 'Content-Type': 'application/json' },
    })
  }

  const body = await req.json()
  console.log('API action:', body.action, 'user:', user.id)
  if (body.action === 'update-plan') return handleUpdatePlan(user.id, body)

  return new Response(JSON.stringify({ error: 'Unknown action' }), {
    status: 400, headers: { ...CORS, 'Content-Type': 'application/json' },
  })
}

// ── Update Stripe subscription plan ──────────────────────────────────────
async function handleUpdatePlan(userId: string, body: { portion: string; cups: number }) {
  const { portion, cups } = body
  const planKey    = `${portion}-${cups}`
  const newPriceId = STRIPE_PRICE_IDS[planKey]

  if (!newPriceId) {
    return new Response(JSON.stringify({ error: `Invalid plan: ${planKey}` }), {
      status: 400, headers: { ...CORS, 'Content-Type': 'application/json' },
    })
  }

  const { data: sub } = await sb.from('subscriptions')
    .select('stripe_subscription_id')
    .eq('customer_id', userId)
    .maybeSingle()

  if (!sub?.stripe_subscription_id) {
    return new Response(JSON.stringify({ success: true, noSubscription: true }), {
      headers: { ...CORS, 'Content-Type': 'application/json' },
    })
  }

  // Get current subscription item ID
  const stripeSub = await stripeReq(`/subscriptions/${sub.stripe_subscription_id}`)
  const itemId    = stripeSub.items?.data[0]?.id

  if (!itemId) {
    return new Response(JSON.stringify({ error: 'Could not find subscription item' }), {
      status: 500, headers: { ...CORS, 'Content-Type': 'application/json' },
    })
  }

  // Swap price with proration
  const params = new URLSearchParams({
    'items[0][id]':       itemId,
    'items[0][price]':    newPriceId,
    'proration_behavior': 'create_prorations',
  })
  const updated = await stripeReq(`/subscriptions/${sub.stripe_subscription_id}`, 'POST', params)

  if (updated.error) {
    console.error('Stripe update failed:', updated.error)
    return new Response(JSON.stringify({ error: updated.error.message || 'Stripe update failed' }), {
      status: 500, headers: { ...CORS, 'Content-Type': 'application/json' },
    })
  }

  // Record confirmed Stripe plan so dashboard can detect future changes correctly
  await sb.from('subscriptions')
    .update({ stripe_plan: planKey })
    .eq('customer_id', userId)

  console.log(`Plan updated for user ${userId}: ${planKey}`)
  return new Response(JSON.stringify({ success: true }), {
    headers: { ...CORS, 'Content-Type': 'application/json' },
  })
}

// ── Checkout completed ────────────────────────────────────────────────────
async function handleCheckoutComplete(session: any) {
  const email  = session.customer_details?.email ?? ''
  const rawRef = session.client_reference_id ?? ''

  const { data: dup } = await sb.from('orders')
    .select('id').eq('stripe_session_id', session.id).maybeSingle()
  if (dup) return

  const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(rawRef)

  if (session.mode === 'subscription' && isUUID) {
    const customerId       = rawRef
    const stripeSubId      = session.subscription
    const stripeCustomerId = session.customer

    if (stripeSubId) {
      await stripeReq(`/subscriptions/${stripeSubId}`, 'POST',
        new URLSearchParams({ 'metadata[supabase_customer_id]': customerId })
      )
    }

    await Promise.all([
      sb.from('subscriptions').upsert(
        { customer_id: customerId, stripe_subscription_id: stripeSubId },
        { onConflict: 'customer_id' }
      ),
      sb.from('customers').upsert(
        { id: customerId, stripe_customer_id: stripeCustomerId },
        { onConflict: 'id' }
      ),
    ])

    // Record the starting stripe_plan so dashboard change-detection works correctly
    const { data: subSettings } = await sb.from('subscriptions')
      .select('portion, chocolate_cups, peanut_butter_cups')
      .eq('customer_id', customerId).maybeSingle()
    if (subSettings) {
      const cups = (subSettings.chocolate_cups ?? 0) + (subSettings.peanut_butter_cups ?? 0)
      await sb.from('subscriptions')
        .update({ stripe_plan: `${subSettings.portion}-${cups}` })
        .eq('customer_id', customerId)
    }

    await insertSubOrder({ customerId, email, sessionId: session.id, amountTotal: session.amount_total })

  } else if (session.mode === 'payment') {
    // Decode base64url (set by website) — fallback to plain string for legacy events
    let ref = rawRef
    try {
      const b64     = rawRef.replace(/-/g, '+').replace(/_/g, '/')
      const padded  = b64 + '='.repeat((4 - b64.length % 4) % 4)
      const decoded = atob(padded)
      ref = new TextDecoder().decode(new Uint8Array(decoded.split('').map(c => c.charCodeAt(0))))
    } catch {
      ref = decodeURIComponent(rawRef)
    }
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

// ── Renewal ───────────────────────────────────────────────────────────────
async function handleRenewal(invoice: any) {
  const { data: dup } = await sb.from('orders')
    .select('id').eq('stripe_invoice_id', invoice.id).maybeSingle()
  if (dup) return

  const stripeSub  = await stripeReq(`/subscriptions/${invoice.subscription}`)
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

// ── Build and insert a subscription order ────────────────────────────────
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
