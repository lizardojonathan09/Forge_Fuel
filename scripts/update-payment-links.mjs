/**
 * One-time script to update all Stripe payment links:
 *  - Enable promotion codes
 *  - Remove custom fields (delivery date)
 *
 * Usage:
 *   STRIPE_SECRET_KEY=sk_live_... node scripts/update-payment-links.mjs
 */

const STRIPE_KEY = process.env.STRIPE_SECRET_KEY;
if (!STRIPE_KEY) {
  console.error('❌  Set STRIPE_SECRET_KEY env var before running.');
  process.exit(1);
}

async function stripeReq(path, method = 'GET', params) {
  const res = await fetch(`https://api.stripe.com/v1${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${STRIPE_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params?.toString(),
  });
  return res.json();
}

// Fetch all payment links (up to 100)
async function listAllPaymentLinks() {
  const links = [];
  let hasMore = true;
  let startingAfter = null;

  while (hasMore) {
    const params = new URLSearchParams({ limit: '100' });
    if (startingAfter) params.set('starting_after', startingAfter);

    const res = await stripeReq(`/payment_links?${params.toString()}`);
    if (res.error) {
      console.error('❌  Error listing payment links:', res.error.message);
      process.exit(1);
    }

    links.push(...res.data);
    hasMore = res.has_more;
    if (hasMore) startingAfter = res.data[res.data.length - 1].id;
  }

  return links;
}

async function updateLink(id) {
  const params = new URLSearchParams();
  params.set('allow_promotion_codes', 'true');
  // Clear all custom fields by passing an empty array
  params.set('custom_fields', '');

  const result = await stripeReq(`/payment_links/${id}`, 'POST', params);
  if (result.error) {
    console.error(`  ❌  Failed: ${result.error.message}`);
    return false;
  }
  return true;
}

(async () => {
  console.log('🔍  Fetching payment links…');
  const links = await listAllPaymentLinks();
  console.log(`   Found ${links.length} payment link(s)\n`);

  for (const link of links) {
    const label = link.metadata?.label || link.id;
    process.stdout.write(`Updating ${link.id}… `);
    const ok = await updateLink(link.id);
    console.log(ok ? '✓' : '✗');
  }

  console.log('\n✅  Done. All payment links updated.');
})();
