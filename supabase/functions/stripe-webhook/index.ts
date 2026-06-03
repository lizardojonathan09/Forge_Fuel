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
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
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
      await handleInvoicePaid(event.data.object)
    } else if (event.type === 'invoice.payment_failed') {
      await handleInvoiceFailed(event.data.object)
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
  if (body.action === 'create-checkout-session') return handleCreateCheckoutSession(user.id, body)
  if (body.action === 'update-plan')             return handleUpdatePlan(user.id, body)
  if (body.action === 'pause-subscription')      return handlePauseResume(user.id, true)
  if (body.action === 'resume-subscription')     return handlePauseResume(user.id, false)
  if (body.action === 'create-portal-session')   return handlePortalSession(user.id, body)
  if (body.action === 'fix-payment-links')       return handleFixPaymentLinks()

  return new Response(JSON.stringify({ error: 'Unknown action' }), {
    status: 400, headers: { ...CORS, 'Content-Type': 'application/json' },
  })
}

// ── Create Stripe Checkout Session ───────────────────────────────────────
async function handleCreateCheckoutSession(userId: string, body: any) {
  const { orderType, cartItems, totalCups, delivery, referral, successUrl, cancelUrl } = body

  if (!cartItems || cartItems.length === 0) {
    return new Response(JSON.stringify({ error: 'Cart is empty' }), {
      status: 400, headers: { ...CORS, 'Content-Type': 'application/json' },
    })
  }

  // Look up existing Stripe customer
  const { data: cust } = await sb.from('customers')
    .select('stripe_customer_id')
    .eq('id', userId)
    .maybeSingle()

  const params = new URLSearchParams()

  // ── Common: metadata ─────────────────────────────────────────────────────
  const meta: Record<string, string> = { supabase_customer_id: userId }
  if (referral)        meta.referral        = referral
  if (delivery?.date)  meta.delivery_date   = delivery.date
  if (delivery?.time)  meta.delivery_time   = delivery.time
  if (delivery?.name)  meta.customer_name   = delivery.name
  if (delivery?.phone) meta.customer_phone  = delivery.phone

  // Per-product qtys in metadata so webhook can read them
  for (const item of cartItems) {
    meta[`qty_${item.productId}`] = String(item.qty)
  }
  meta.flavor = cartItems.map((i: any) => `${i.qty} ${i.name}`).join(' + ')

  Object.entries(meta).forEach(([k, v]) => params.set(`metadata[${k}]`, v))

  // ── Customer attachment ──────────────────────────────────────────────────
  if (cust?.stripe_customer_id) {
    params.set('customer', cust.stripe_customer_id)
  } else if (delivery?.email) {
    params.set('customer_email', delivery.email)
  }

  params.set('allow_promotion_codes', 'true')
  params.set('success_url', successUrl)
  params.set('cancel_url',  cancelUrl)

  if (orderType === 'subscribe') {
    // ── SUBSCRIPTION MODE ────────────────────────────────────────────────
    params.set('mode', 'subscription')
    params.set('client_reference_id', userId)  // UUID signals subscription mode to webhook

    const fullQty = cartItems.filter((i: any) => i.type === 'full').reduce((s: number, i: any) => s + i.qty, 0)
    const halfQty = cartItems.filter((i: any) => i.type === 'half').reduce((s: number, i: any) => s + i.qty, 0)
    const cups    = totalCups as number

    // Use a pre-created price ID when the cart is a pure full or pure half order
    let priceId: string | undefined
    if (halfQty === 0) {
      priceId = cups >= 7 ? STRIPE_PRICE_IDS['full-7'] : cups >= 5 ? STRIPE_PRICE_IDS['full-5'] : STRIPE_PRICE_IDS['full-3']
    } else if (fullQty === 0) {
      priceId = cups >= 9 ? STRIPE_PRICE_IDS['half-9'] : cups >= 7 ? STRIPE_PRICE_IDS['half-7'] : STRIPE_PRICE_IDS['half-5']
    }

    if (priceId) {
      params.set('line_items[0][price]',    priceId)
      params.set('line_items[0][quantity]', '1')
    } else {
      // Mixed cart — create an ad-hoc recurring price from the cart total
      const totalCents = cartItems.reduce((s: number, i: any) => s + i.unitPrice * i.qty, 0)
      params.set('line_items[0][price_data][currency]',                         'usd')
      params.set('line_items[0][price_data][unit_amount]',                      String(totalCents))
      params.set('line_items[0][price_data][product_data][name]',               'Forge Oats Weekly Pack')
      params.set('line_items[0][price_data][product_data][description]',        meta.flavor)
      params.set('line_items[0][price_data][recurring][interval]',              'week')
      params.set('line_items[0][quantity]', '1')
    }

  } else {
    // ── ONE-TIME PAYMENT MODE ────────────────────────────────────────────
    params.set('mode', 'payment')

    // Encode client_reference_id for webhook parseRef compatibility
    const refParts = [`${totalCups}pack`]
    for (const item of cartItems) refParts.push(`${item.productId}:${item.qty}`)
    if (referral)       refParts.push(`ref:${referral}`)
    if (delivery?.date) refParts.push(`date:${delivery.date}`)
    if (delivery?.time) refParts.push(`time:${delivery.time}`)
    if (delivery?.name) refParts.push(`name:${delivery.name}`)

    const refStr  = refParts.join('|')
    const refBytes = new TextEncoder().encode(refStr)
    const encoded  = btoa(String.fromCharCode(...refBytes))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    params.set('client_reference_id', encoded)

    // One line item per product
    cartItems.forEach((item: any, idx: number) => {
      const serving = item.type === 'full' ? 'Full Serving' : 'Half Serving'
      params.set(`line_items[${idx}][price_data][currency]`,                  'usd')
      params.set(`line_items[${idx}][price_data][unit_amount]`,               String(item.unitPrice))
      params.set(`line_items[${idx}][price_data][product_data][name]`,        item.name)
      params.set(`line_items[${idx}][price_data][product_data][description]`, `${serving} — Forge Performance Oats`)
      params.set(`line_items[${idx}][quantity]`,                              String(item.qty))
    })
  }

  const session = await stripeReq('/checkout/sessions', 'POST', params)

  if (session.error) {
    console.error('Checkout session error:', session.error)
    return new Response(JSON.stringify({ error: session.error.message || 'Failed to create checkout session' }), {
      status: 500, headers: { ...CORS, 'Content-Type': 'application/json' },
    })
  }

  console.log(`Checkout session created for user ${userId}: ${session.id} (${orderType})`)
  return new Response(JSON.stringify({ url: session.url }), {
    headers: { ...CORS, 'Content-Type': 'application/json' },
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

// ── Pause or resume Stripe subscription ──────────────────────────────────
async function handlePauseResume(userId: string, pause: boolean) {
  const { data: sub } = await sb.from('subscriptions')
    .select('stripe_subscription_id')
    .eq('customer_id', userId)
    .maybeSingle()

  if (!sub?.stripe_subscription_id) {
    return new Response(JSON.stringify({ success: true, noSubscription: true }), {
      headers: { ...CORS, 'Content-Type': 'application/json' },
    })
  }

  const params = pause
    ? new URLSearchParams({ 'pause_collection[behavior]': 'void' })
    : new URLSearchParams({ 'pause_collection': '' })

  const updated = await stripeReq(`/subscriptions/${sub.stripe_subscription_id}`, 'POST', params)

  if (updated.error) {
    console.error('Stripe pause/resume failed:', updated.error)
    return new Response(JSON.stringify({ error: updated.error.message || 'Stripe update failed' }), {
      status: 500, headers: { ...CORS, 'Content-Type': 'application/json' },
    })
  }

  console.log(`Subscription ${pause ? 'paused' : 'resumed'} for user ${userId}`)
  return new Response(JSON.stringify({ success: true }), {
    headers: { ...CORS, 'Content-Type': 'application/json' },
  })
}

// ── One-time: fix all payment links ──────────────────────────────────────
async function handleFixPaymentLinks() {
  const results: { id: string; ok: boolean; error?: string }[] = []

  // Fetch all payment links
  let hasMore = true
  let startingAfter = ''
  const links: any[] = []

  while (hasMore) {
    const qs = new URLSearchParams({ limit: '100' })
    if (startingAfter) qs.set('starting_after', startingAfter)
    const res = await stripeReq(`/payment_links?${qs}`)
    if (res.error) {
      return new Response(JSON.stringify({ error: res.error.message }), {
        status: 500, headers: { ...CORS, 'Content-Type': 'application/json' },
      })
    }
    links.push(...res.data)
    hasMore = res.has_more
    if (hasMore) startingAfter = res.data[res.data.length - 1].id
  }

  // Update each link
  for (const link of links) {
    const params = new URLSearchParams({
      'allow_promotion_codes': 'true',
      'custom_fields':         '',
    })
    const updated = await stripeReq(`/payment_links/${link.id}`, 'POST', params)
    if (updated.error) {
      results.push({ id: link.id, ok: false, error: updated.error.message })
    } else {
      results.push({ id: link.id, ok: true })
    }
  }

  console.log('fix-payment-links results:', JSON.stringify(results))
  return new Response(JSON.stringify({ results }), {
    headers: { ...CORS, 'Content-Type': 'application/json' },
  })
}

// ── Stripe Customer Portal session ───────────────────────────────────────
async function handlePortalSession(userId: string, body: { returnUrl: string }) {
  const { data: cust } = await sb.from('customers')
    .select('stripe_customer_id')
    .eq('id', userId)
    .maybeSingle()

  if (!cust?.stripe_customer_id) {
    return new Response(JSON.stringify({ error: 'No Stripe customer found' }), {
      status: 404, headers: { ...CORS, 'Content-Type': 'application/json' },
    })
  }

  const session = await stripeReq('/billing_portal/sessions', 'POST', new URLSearchParams({
    customer:   cust.stripe_customer_id,
    return_url: body.returnUrl,
  }))

  if (session.error) {
    console.error('Portal session error:', session.error)
    return new Response(JSON.stringify({ error: session.error.message || 'Failed to create portal session' }), {
      status: 500, headers: { ...CORS, 'Content-Type': 'application/json' },
    })
  }

  return new Response(JSON.stringify({ url: session.url }), {
    headers: { ...CORS, 'Content-Type': 'application/json' },
  })
}

// ── Invoice paid — clear payment_failed flag + handle renewal ─────────────
async function handleInvoicePaid(invoice: any) {
  // Clear payment_failed flag for this subscription
  const stripeSub  = await stripeReq(`/subscriptions/${invoice.subscription}`)
  const customerId = stripeSub.metadata?.supabase_customer_id
  if (customerId) {
    await sb.from('subscriptions')
      .update({ payment_failed: false })
      .eq('customer_id', customerId)
  }

  // Create renewal order for billing cycle payments
  if (invoice.billing_reason === 'subscription_cycle') {
    await handleRenewal(invoice)
  }
}

// ── Invoice failed — set payment_failed flag ──────────────────────────────
async function handleInvoiceFailed(invoice: any) {
  const stripeSub  = await stripeReq(`/subscriptions/${invoice.subscription}`)
  const customerId = stripeSub.metadata?.supabase_customer_id
  if (!customerId) {
    console.warn('No supabase_customer_id in subscription metadata, skipping')
    return
  }

  await sb.from('subscriptions')
    .update({ payment_failed: true })
    .eq('customer_id', customerId)

  console.log(`Payment failed flagged for customer ${customerId}`)
}

// ── Checkout completed ────────────────────────────────────────────────────
async function handleCheckoutComplete(session: any) {
  // Only process sessions where payment was actually collected
  if (session.payment_status !== 'paid') {
    console.warn('Skipping checkout.session.completed — payment_status:', session.payment_status)
    return
  }

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

    // Extract per-product qtys and referral from session metadata
    const meta      = session.metadata ?? {}
    const qtyFc     = parseInt(meta.qty_fc ?? '0') || 0
    const qtyFp     = parseInt(meta.qty_fp ?? '0') || 0
    const qtyHc     = parseInt(meta.qty_hc ?? '0') || 0
    const qtyHp     = parseInt(meta.qty_hp ?? '0') || 0
    const referral  = meta.referral ?? null
    const fullCups  = qtyFc + qtyFp
    const halfCups  = qtyHc + qtyHp
    const portion   = fullCups >= halfCups ? 'full' : 'half'
    const totalCups = qtyFc + qtyFp + qtyHc + qtyHp

    if (stripeSubId) {
      await stripeReq(`/subscriptions/${stripeSubId}`, 'POST',
        new URLSearchParams({ 'metadata[supabase_customer_id]': customerId })
      )
    }

    await Promise.all([
      sb.from('subscriptions').upsert(
        {
          customer_id:            customerId,
          stripe_subscription_id: stripeSubId,
          qty_fc:                 qtyFc,
          qty_fp:                 qtyFp,
          qty_hc:                 qtyHc,
          qty_hp:                 qtyHp,
          chocolate_cups:         qtyFc + qtyHc,   // legacy
          peanut_butter_cups:     qtyFp + qtyHp,   // legacy
          portion,                                  // legacy
          ...(totalCups > 0 ? { stripe_plan: `${portion}-${totalCups}` } : {}),
        },
        { onConflict: 'customer_id' }
      ),
      sb.from('customers').upsert(
        { id: customerId, stripe_customer_id: stripeCustomerId },
        { onConflict: 'id' }
      ),
    ])

    // If qtys weren't in metadata (legacy flow), fall back to reading existing row
    if (totalCups === 0) {
      const { data: subSettings } = await sb.from('subscriptions')
        .select('portion, chocolate_cups, peanut_butter_cups')
        .eq('customer_id', customerId).maybeSingle()
      if (subSettings) {
        const cups = (subSettings.chocolate_cups ?? 0) + (subSettings.peanut_butter_cups ?? 0)
        await sb.from('subscriptions')
          .update({ stripe_plan: `${subSettings.portion}-${cups}` })
          .eq('customer_id', customerId)
      }
    }

    await insertSubOrder({ customerId, email, sessionId: session.id, amountTotal: session.amount_total, referredBy: referral })

  } else if (session.mode === 'payment') {
    let parsed: Record<string, any> = {}

    if (rawRef) {
      // Decode base64url (set by website) — fallback to plain string for legacy events
      try {
        const b64     = rawRef.replace(/-/g, '+').replace(/_/g, '/')
        const padded  = b64 + '='.repeat((4 - b64.length % 4) % 4)
        const decoded = atob(padded)
        const str     = new TextDecoder().decode(new Uint8Array(decoded.split('').map(c => c.charCodeAt(0))))
        parsed = parseRef(str)
      } catch {
        parsed = parseRef(decodeURIComponent(rawRef))
      }
    } else {
      // No client_reference_id — customer came directly via payment link.
      // Extract what we can from the session itself.
      parsed = extractFromSession(session)
    }

    const { data: customer } = await sb.from('customers')
      .select('id').eq('email', email).maybeSingle()

    // Per-product qtys — prefer metadata, fall back to encoded ref fields
    const meta  = session.metadata ?? {}
    const qtyFc = parseInt(meta.qty_fc ?? parsed.fc ?? '0') || 0
    const qtyFp = parseInt(meta.qty_fp ?? parsed.fp ?? '0') || 0
    const qtyHc = parseInt(meta.qty_hc ?? parsed.hc ?? '0') || 0
    const qtyHp = parseInt(meta.qty_hp ?? parsed.hp ?? '0') || 0

    await sb.from('orders').insert({
      customer_id:       customer?.id ?? null,
      customer_email:    email,
      customer_name:     parsed.name ?? meta.customer_name ?? session.customer_details?.name ?? '',
      customer_phone:    parsed.phone ?? meta.customer_phone ?? session.customer_details?.phone ?? null,
      qty_fc:            qtyFc,
      qty_fp:            qtyFp,
      qty_hc:            qtyHc,
      qty_hp:            qtyHp,
      flavor:            meta.flavor || parsed.flavor || '',
      portion:           parsed.portion ?? '',
      pack_size:         parsed.pack_size ?? null,
      order_type:        'one-time',
      total:             parsed.price ?? formatAmount(session.amount_total),
      delivery_date:     parsed.date ?? meta.delivery_date ?? '',
      delivery_time:     parsed.time ?? meta.delivery_time ?? '',
      referred_by:       parsed.ref ?? meta.referral ?? null,
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
async function insertSubOrder({ customerId, email, sessionId, invoiceId, amountTotal, referredBy }: {
  customerId:   string
  email:        string
  sessionId?:   string
  invoiceId?:   string
  amountTotal?: number | null
  referredBy?:  string | null
}) {
  const [{ data: sub }, { data: cust }] = await Promise.all([
    sb.from('subscriptions').select('*').eq('customer_id', customerId).maybeSingle(),
    sb.from('customers').select('name,phone').eq('id', customerId).maybeSingle(),
  ])
  if (!sub) {
    console.warn('No subscription found for customer', customerId)
    return
  }

  // Read per-product qtys — prefer new columns, fall back to old schema
  let fc = sub.qty_fc ?? 0
  let fp = sub.qty_fp ?? 0
  let hc = sub.qty_hc ?? 0
  let hp = sub.qty_hp ?? 0

  if (fc + fp + hc + hp === 0) {
    // Legacy fallback: derive from chocolate_cups + peanut_butter_cups + portion
    const choc = sub.chocolate_cups ?? 0
    const pb   = sub.peanut_butter_cups ?? 0
    if (sub.portion === 'half') { hc = choc; hp = pb }
    else                         { fc = choc; fp = pb }
  }

  const cups     = fc + fp + hc + hp
  const flavors: string[] = []
  if (fc > 0) flavors.push(`${fc} Full Chocolate`)
  if (fp > 0) flavors.push(`${fp} Full Peanut Butter`)
  if (hc > 0) flavors.push(`${hc} Half Chocolate`)
  if (hp > 0) flavors.push(`${hp} Half Peanut Butter`)

  // Determine dominant portion for price-tier lookup
  const fullCups = fc + fp
  const halfCups = hc + hp
  const portion  = fullCups >= halfCups ? 'full' : 'half'

  const basePerCup = PER_CUP[`${portion}-${cups}`] ?? 7.50
  const total = amountTotal != null
    ? formatAmount(amountTotal)
    : '$' + (basePerCup * cups * (1 - SUB_DISC)).toFixed(2)

  await sb.from('orders').insert({
    customer_id:       customerId,
    customer_email:    email,
    customer_name:     cust?.name ?? '',
    customer_phone:    cust?.phone ?? null,
    qty_fc:            fc,
    qty_fp:            fp,
    qty_hc:            hc,
    qty_hp:            hp,
    flavor:            flavors.join(' + ') || 'Chocolate',
    portion:           portion === 'half' ? 'Half Serving' : 'Full Serving',
    pack_size:         cups,
    order_type:        'subscribe',
    total,
    delivery_date:     sub.delivery_day  ?? '',
    delivery_time:     sub.delivery_time ?? '',
    referred_by:       referredBy ?? null,
    stripe_session_id: sessionId ?? null,
    stripe_invoice_id: invoiceId ?? null,
  })
}

// ── Extract order data from session when client_reference_id is absent ────
// Used when a customer purchases directly via a Stripe payment link
// (bypassing the website), so no encoded data was attached.
function extractFromSession(session: any): Record<string, any> {
  const parsed: Record<string, any> = {}

  // Name & phone from customer_details
  parsed.name  = session.customer_details?.name  ?? ''
  parsed.phone = session.customer_details?.phone ?? null

  // Delivery time from custom fields (if still present on the link)
  const fields: any[] = session.custom_fields ?? []
  const dtField = fields.find((f: any) => f.key === 'preferreddeliverydateandtime')
  if (dtField?.text?.value) parsed.time = dtField.text.value

  // Infer portion & pack_size from amount_subtotal (unique per plan, discount-independent)
  const cents = session.amount_subtotal ?? session.amount_total ?? 0
  const PLAN_BY_CENTS: Record<number, { portion: string; pack_size: number }> = {
    2400: { portion: 'Full Serving', pack_size: 3 },
    3750: { portion: 'Full Serving', pack_size: 5 },
    4900: { portion: 'Full Serving', pack_size: 7 },
    2500: { portion: 'Half Serving', pack_size: 5 },
    3150: { portion: 'Half Serving', pack_size: 7 },
    3600: { portion: 'Half Serving', pack_size: 9 },
  }
  const plan = PLAN_BY_CENTS[cents]
  if (plan) {
    parsed.portion   = plan.portion
    parsed.pack_size = plan.pack_size
  }

  // Total from session
  parsed.price = formatAmount(session.amount_total)

  // Flavor cannot be determined from the payment link alone — left blank
  parsed.flavor = ''

  return parsed
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
