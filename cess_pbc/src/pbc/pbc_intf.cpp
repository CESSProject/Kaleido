/* pbc-intf.c -- Interface between Rust and PBC libs */

/*
Copyright (c) 2018 Emotiq AG

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */

#include "pbc_intf.hpp"

// ---------------------------------------------------
// for initial interface testing...

extern "C" uint64_t echo(uint64_t nel, char *msg_in, char *msg_out)
{
  memcpy(msg_out, msg_in, nel);
  return nel;
}

// ---------------------------------------------------

typedef struct pairing_context
{
  bool init_flag;
  pairing_t pairing;
  element_t g1_gen;
  element_t g2_gen;
} pairing_context_t;

typedef struct Zr_context
{
  bool init_flag;   // true if context is initialized
  pairing_t pairing;//pairing generated from security parameters
  element_t zr_gen;//element Zr
} Zr_context_t;

pairing_context_t context[16];
Zr_context_t zr_context[16];

static inline bool &IsInit(uint64_t ctxt)
{
  return context[ctxt].init_flag;
}

static inline pairing_t &Pairing(uint64_t ctxt)
{
  return context[ctxt].pairing;
}

static inline element_t &G1_gen(uint64_t ctxt)
{
  return context[ctxt].g1_gen;
}

static inline element_t &G2_gen(uint64_t ctxt)
{
  return context[ctxt].g2_gen;
}


static inline bool &IsZrInit(uint64_t ctxt)
{
  return zr_context[ctxt].init_flag;
}
static inline element_t &zr_gen(uint64_t ctxt)
{
  return zr_context[ctxt].zr_gen;
}
static inline pairing_t &zr_Pairing(uint64_t ctxt)
{
  return zr_context[ctxt].pairing;
}

// -------------------------------------------------

extern "C" bool is_pairing_symmetric(uint64_t ctxt) {
  return pairing_is_symmetric(Pairing(ctxt));
}

extern "C" int64_t init_pairing(uint64_t ctxt, char *param_str, uint64_t nel, uint64_t *psize)
{
  int64_t ans = -1;

  if (IsInit(ctxt))
  {
    element_clear(G1_gen(ctxt));
    element_clear(G2_gen(ctxt));
    pairing_clear(Pairing(ctxt));
    IsInit(ctxt) = false;
  }
  ans = pairing_init_set_buf(Pairing(ctxt), param_str, nel);
  if (0 == ans)
  {
    element_t z, pair;

    element_init_G1(G1_gen(ctxt), Pairing(ctxt));
    element_init_G2(G2_gen(ctxt), Pairing(ctxt));

    element_init_GT(pair, Pairing(ctxt)); // archetypes for sizing info
    element_init_Zr(z, Pairing(ctxt));

    element_random(G1_gen(ctxt)); // default random values
    element_random(G2_gen(ctxt));

    psize[0] = element_length_in_bytes_compressed(G1_gen(ctxt));
    psize[1] = element_length_in_bytes_compressed(G2_gen(ctxt));
    psize[2] = element_length_in_bytes(pair);
    psize[3] = element_length_in_bytes(z);

    element_clear(pair);
    element_clear(z);

    IsInit(ctxt) = true;
  }
  return ans;
}

extern "C" int64_t set_g1(uint64_t ctxt,
                          uint8_t *pbuf)
{
  // NOTE: Changing G1 and/or G2 generators invalidates all keying.
  return element_from_bytes_compressed(G1_gen(ctxt), pbuf);
}

extern "C" int64_t set_g2(uint64_t ctxt,
                          uint8_t *pbuf)
{
  // NOTE: Changing G1 and/or G2 generators invalidates all keying.
  return element_from_bytes_compressed(G2_gen(ctxt), pbuf);
}

// --------------------------------------------

extern "C" void make_key_pair(uint64_t ctxt,
                              uint8_t *pskey, uint8_t *ppkey,
                              uint8_t *phash, uint64_t nhash)
{
  element_t skey, pkey;
  element_init_Zr(skey, Pairing(ctxt));
  element_init_G2(pkey, Pairing(ctxt));

  element_from_hash(skey, phash, nhash);
  element_pow_zn(pkey, G2_gen(ctxt), skey);
  element_to_bytes(pskey, skey);
  element_to_bytes_compressed(ppkey, pkey);

  element_clear(skey);
  element_clear(pkey);
}

extern "C" void sign_hash(uint64_t ctxt,
                          uint8_t *psig, uint8_t *pskey,
                          uint8_t *phash, uint64_t nhash)
{
  element_t sig, skey;

  element_init_G1(sig, Pairing(ctxt));
  element_init_Zr(skey, Pairing(ctxt));
  element_from_hash(sig, phash, nhash);
  element_from_bytes(skey, pskey);
  element_pow_zn(sig, sig, skey);
  element_to_bytes_compressed(psig, sig);
  element_clear(sig);
  element_clear(skey);
}

extern "C" void make_public_subkey(uint64_t ctxt,
                                   uint8_t *abuf,
                                   uint8_t *pkey,
                                   uint8_t *phash_id, uint64_t nhash)
{
  element_t z;
  element_t gx, gp;

  element_init_Zr(z, Pairing(ctxt));
  element_init_G2(gx, Pairing(ctxt));
  element_init_G2(gp, Pairing(ctxt));
  element_from_bytes_compressed(gp, pkey);
  element_from_hash(z, phash_id, nhash);
  element_pow_zn(gx, G2_gen(ctxt), z);
  element_mul(gp, gx, gp);
  element_to_bytes_compressed(abuf, gp); // ans is G2
  element_clear(z);
  element_clear(gx);
  element_clear(gp);
}

extern "C" void make_secret_subkey(uint64_t ctxt,
                                   uint8_t *abuf,
                                   uint8_t *skey,
                                   uint8_t *phash_id, uint64_t nhash)
{
  element_t z, zs, s;

  element_init_Zr(z, Pairing(ctxt));
  element_init_Zr(zs, Pairing(ctxt));
  element_init_G1(s, Pairing(ctxt));
  element_from_hash(z, phash_id, nhash); // get ID
  element_from_bytes(zs, skey);          // user's secret key
  element_add(z, z, zs);
  element_invert(z, z);
  element_pow_zn(s, G1_gen(ctxt), z);
  element_to_bytes_compressed(abuf, s); // ans is G1
  element_clear(z);
  element_clear(zs);
  element_clear(s);
}

extern "C" void compute_pairing(uint64_t ctxt,
                                uint8_t *gtbuf,
                                uint8_t *hbuf,
                                uint8_t *gbuf)
{
  element_t hh, gg, pair;

  element_init_G1(hh, Pairing(ctxt));
  element_init_G2(gg, Pairing(ctxt));
  element_init_GT(pair, Pairing(ctxt));

  element_from_bytes_compressed(hh, hbuf);
  element_from_bytes_compressed(gg, gbuf);
  pairing_apply(pair, hh, gg, Pairing(ctxt));
  element_to_bytes(gtbuf, pair);
  element_clear(pair);
  element_clear(hh);
  element_clear(gg);
}

extern "C" void sakai_kasahara_encrypt(uint64_t ctxt,
                                       uint8_t *rbuf, // R result in G2
                                       uint8_t *pbuf, // pairing result in GT
                                       uint8_t *pkey, // public subkey in G2
                                       uint8_t *phash, uint64_t nhash)
{
  element_t zr, gt, pk;

  /* pk, pkey is the public-subkey */
  /* phash, zr is the hash(ID || Tstamp || msg) */
  /* result R = zr*Psubkey */
  /* result pairing e(zr*U,Psubkey) = e(U,zr*Psubkey) */

  element_init_G2(pk, Pairing(ctxt));
  element_init_Zr(zr, Pairing(ctxt));
  element_init_GT(gt, Pairing(ctxt));
  element_from_bytes_compressed(pk, pkey);
  element_from_hash(zr, phash, nhash);
  element_pow_zn(pk, pk, zr);
  element_to_bytes_compressed(rbuf, pk);

  element_pow_zn(pk, G2_gen(ctxt), zr);
  pairing_apply(gt, G1_gen(ctxt), pk, Pairing(ctxt));
  element_to_bytes(pbuf, gt);

  element_clear(zr);
  element_clear(gt);
  element_clear(pk);
}

extern "C" void sakai_kasahara_decrypt(uint64_t ctxt,
                                       uint8_t *pbuf, // pairing result in GT
                                       uint8_t *rbuf, // R pt in G2
                                       uint8_t *sbuf) // secret subkey in G1
{
  element_t gt, sk, rk;

  /* rk, rbuf is the R value from encryption */
  /* sk, sbuf is the secret_subkey */

  element_init_G1(sk, Pairing(ctxt));
  element_init_G2(rk, Pairing(ctxt));
  element_init_GT(gt, Pairing(ctxt));
  element_from_bytes_compressed(sk, sbuf);
  element_from_bytes_compressed(rk, rbuf);
  pairing_apply(gt, sk, rk, Pairing(ctxt));
  element_to_bytes(pbuf, gt);
  element_clear(sk);
  element_clear(rk);
  element_clear(gt);
}

extern "C" int64_t sakai_kasahara_check(uint64_t ctxt,
                                        uint8_t *rkey, // R in G2
                                        uint8_t *pkey, // public subkey in G2
                                        uint8_t *phash, uint64_t nhash)
{
  element_t zr, pk1, pk2;
  int64_t ans;

  /* rkey, pk2 is the R value from encryption */
  /* pkey, pk1 is the public_subkey */
  /* phash is hash(ID || Tstamp || msg) */

  element_init_G2(pk1, Pairing(ctxt));
  element_init_G2(pk2, Pairing(ctxt));
  element_init_Zr(zr, Pairing(ctxt));
  element_from_bytes_compressed(pk1, pkey);
  element_from_bytes_compressed(pk2, rkey);
  element_from_hash(zr, phash, nhash);
  element_pow_zn(pk1, pk1, zr);
  ans = element_cmp(pk1, pk2);
  element_clear(pk1);
  element_clear(pk2);
  element_clear(zr);
  return ans;
}

// -----------------------------------------------------------------

static uint64_t get_datum(element_t elt, uint8_t *pbuf, uint64_t buflen, bool cmpr = true)
{
  uint64_t len;

  if (cmpr)
    len = element_length_in_bytes_compressed(elt);
  else
    len = element_length_in_bytes(elt);

  if (NULL != pbuf)
  {
    if (buflen < len)
      return 0;
    if (cmpr)
      element_to_bytes_compressed(pbuf, elt);
    else
      element_to_bytes(pbuf, elt);
  }
  return len;
}

extern "C" uint64_t get_g2(uint64_t ctxt,
                           uint8_t *pbuf, uint64_t buflen)
{
  return get_datum(G2_gen(ctxt), pbuf, buflen);
}

extern "C" uint64_t get_g1(uint64_t ctxt,
                           uint8_t *pbuf, uint64_t buflen)
{
  return get_datum(G1_gen(ctxt), pbuf, buflen);
}


extern "C" uint64_t get_random_g1(uint64_t ctxt,
                           uint8_t *pbuf, uint64_t buflen)
{
  element_t g1;
  uint64_t len;
  element_init_G1(g1, Pairing(ctxt));
  element_random(g1);
  len = get_datum(g1, pbuf, buflen);
  element_clear(g1);
  return len;
}

// ------------------------------------------------

extern "C" int64_t check_signature(uint64_t ctxt,
                                   uint8_t *psig,
                                   uint8_t *phash, uint64_t nhash,
                                   uint8_t *pkey)
{
  element_t ptHash, ptPKey, ptSig, pair1, pair2;
  int64_t tf;
  element_init_G1(ptHash, Pairing(ctxt));
  element_init_G1(ptSig, Pairing(ctxt));
  element_init_G2(ptPKey, Pairing(ctxt));
  element_init_GT(pair1, Pairing(ctxt));
  element_init_GT(pair2, Pairing(ctxt));

  element_from_bytes_compressed(ptSig, psig);
  element_from_hash(ptHash, phash, nhash);
  element_from_bytes_compressed(ptPKey, pkey);
  pairing_apply(pair1, ptSig, G2_gen(ctxt), Pairing(ctxt));
  pairing_apply(pair2, ptHash, ptPKey, Pairing(ctxt));
  tf = element_cmp(pair1, pair2);

  element_clear(ptHash);
  element_clear(ptPKey);
  element_clear(ptSig);
  element_clear(pair1);
  element_clear(pair2);

  return tf;
}

// ----------------------------------------------
// PBC Library does not handle incoming zero (identity) values very
// well, often returning total garbage in such cases. Instead, we must
// take precautions ourselves.

static bool tst_nonzero(uint8_t *ptr, uint64_t nel)
{
  // search operand for a non-zero byte
  // this version assumes at least 8 bytes of memory in buffer
  return ((0 != ((uint64_t *)ptr)[0]) ||
          (0 != memcmp(ptr, ptr + 8, nel - 8)));

  /*
  uint64_t *p64 = (uint64_t*)ptr;
  for(long ix = (nel >> 3); --ix >= 0; )
    if(*p64++)
      return true;
  uint32_t *p32 = (uint32_t*)p64;
  if((nel & 4) && (*(uint32_t*)ptr++))
    return true;
  uint16_t *p16 = (uint16_t*)p32;
  if((nel & 2) && (*(uint16_t*)ptr++))
    return true;
  uint8_t *p8 = (uint8_t*)p16;
  if((nel & 1) && *p8)
    return true;
  return false;
  */
  /*
  for(long ix = nel; --ix >= 0;)
    if(ptr[ix])
      return true;
  return false;
  */
}

// ----------------------------------------------

extern "C" void add_G1_pts(uint64_t ctxt,
                           uint8_t *pt1, uint8_t *pt2)
{
  element_t p1, p2;
  int nel;
  element_init_G1(p1, Pairing(ctxt));
  nel = element_length_in_bytes_compressed(p1);
  if (tst_nonzero(pt1, nel))
  {
    if (tst_nonzero(pt2, nel))
    {
      element_init_G1(p2, Pairing(ctxt));
      element_from_bytes_compressed(p1, pt1);
      element_from_bytes_compressed(p2, pt2);
      element_add(p1, p1, p2);
      element_clear(p2);
      if (element_is0(p1))
        memset(pt1, 0, nel);
      else
        element_to_bytes_compressed(pt1, p1);
    }
  }
  else if (tst_nonzero(pt2, nel))
    memcpy(pt1, pt2, nel);
  element_clear(p1);
}

extern "C" void sub_G1_pts(uint64_t ctxt,
                           uint8_t *pt1, uint8_t *pt2)
{
  element_t p1, p2;
  int nel;
  element_init_G1(p1, Pairing(ctxt));
  nel = element_length_in_bytes_compressed(p1);
  if (tst_nonzero(pt1, nel))
  {
    if (tst_nonzero(pt2, nel))
    {
      element_init_G1(p2, Pairing(ctxt));
      element_from_bytes_compressed(p1, pt1);
      element_from_bytes_compressed(p2, pt2);
      element_sub(p1, p1, p2);
      element_clear(p2);
      if (element_is0(p1))
        memset(pt1, 0, nel);
      else
        element_to_bytes_compressed(pt1, p1);
    }
  }
  else if (tst_nonzero(pt2, nel))
  {
    element_from_bytes_compressed(p1, pt2);
    element_neg(p1, p1);
    element_to_bytes_compressed(pt1, p1);
  }
  element_clear(p1);
}

extern "C" void mul_G1_pts(uint64_t ctxt,
                           uint8_t *pt1, uint8_t *pt2)
{
  element_t p1, p2;
  int nel;
  element_init_G1(p1, Pairing(ctxt));
  nel = element_length_in_bytes_compressed(p1);
  if (tst_nonzero(pt1, nel))
  {
    if (tst_nonzero(pt2, nel))
    {
      element_init_G1(p2, Pairing(ctxt));
      element_from_bytes_compressed(p1, pt1);
      element_from_bytes_compressed(p2, pt2);
      element_mul(p1, p1, p2);
      element_clear(p2);
      if (element_is0(p1))
        memset(pt1, 0, nel);
      else
        element_to_bytes_compressed(pt1, p1);
    }
  }
  else if (tst_nonzero(pt2, nel))
    memcpy(pt1, pt2, nel);
  element_clear(p1);
}

extern "C" void div_G1_pts(uint64_t ctxt,
                           uint8_t *pt1, uint8_t *pt2)
{
  element_t p1, p2;
  int nel;
  element_init_G1(p1, Pairing(ctxt));
  nel = element_length_in_bytes_compressed(p1);
  if (tst_nonzero(pt1, nel))
  {
    if (tst_nonzero(pt2, nel))
    {
      element_init_G1(p2, Pairing(ctxt));
      element_from_bytes_compressed(p1, pt1);
      element_from_bytes_compressed(p2, pt2);
      element_div(p1, p1, p2);
      element_clear(p2);
      if (element_is0(p1))
        memset(pt1, 0, nel);
      else
        element_to_bytes_compressed(pt1, p1);
    }
  }
  else if (tst_nonzero(pt2, nel))
  {
    element_from_bytes_compressed(p1, pt2);
    element_invert(p1, p1);
    element_to_bytes_compressed(pt1, p1);
  }
  element_clear(p1);
}

extern "C" void neg_G1_pt(uint64_t ctxt,
                          uint8_t *pt1)
{
  element_t p1;
  int nel;
  element_init_G1(p1, Pairing(ctxt));
  nel = element_length_in_bytes_compressed(p1);
  if (tst_nonzero(pt1, nel))
  {
    element_from_bytes_compressed(p1, pt1);
    element_neg(p1, p1);
    element_to_bytes_compressed(pt1, p1);
  }
  element_clear(p1);
}

extern "C" void inv_G1_pt(uint64_t ctxt,
                          uint8_t *pt1)
{
  element_t p1;
  int nel;
  element_init_G1(p1, Pairing(ctxt));
  nel = element_length_in_bytes_compressed(p1);
  if (tst_nonzero(pt1, nel))
  {
    element_from_bytes_compressed(p1, pt1);
    element_invert(p1, p1);
    element_to_bytes_compressed(pt1, p1);
  }
  element_clear(p1);
}

// ----------------------------------------------

extern "C" void add_G2_pts(uint64_t ctxt,
                           uint8_t *pt1, uint8_t *pt2)
{
  element_t p1, p2;
  int nel;
  element_init_G2(p1, Pairing(ctxt));
  nel = element_length_in_bytes_compressed(p1);
  if (tst_nonzero(pt1, nel))
  {
    if (tst_nonzero(pt2, nel))
    {
      element_init_G2(p2, Pairing(ctxt));
      element_from_bytes_compressed(p1, pt1);
      element_from_bytes_compressed(p2, pt2);
      element_add(p1, p1, p2);
      element_clear(p2);
      if (element_is0(p1))
        memset(pt1, 0, nel);
      else
        element_to_bytes_compressed(pt1, p1);
    }
  }
  else if (tst_nonzero(pt2, nel))
    memcpy(pt1, pt2, nel);
  element_clear(p1);
}

extern "C" void sub_G2_pts(uint64_t ctxt,
                           uint8_t *pt1, uint8_t *pt2)
{
  element_t p1, p2;
  int nel;
  element_init_G2(p1, Pairing(ctxt));
  nel = element_length_in_bytes_compressed(p1);
  if (tst_nonzero(pt1, nel))
  {
    if (tst_nonzero(pt2, nel))
    {
      element_init_G2(p2, Pairing(ctxt));
      element_from_bytes_compressed(p1, pt1);
      element_from_bytes_compressed(p2, pt2);
      element_sub(p1, p1, p2);
      element_clear(p2);
      if (element_is0(p1))
        memset(pt1, 0, nel);
      else
        element_to_bytes_compressed(pt1, p1);
    }
  }
  else if (tst_nonzero(pt2, nel))
  {
    element_from_bytes_compressed(p1, pt2);
    element_neg(p1, p1);
    element_to_bytes_compressed(pt1, p1);
  }
  element_clear(p1);
}

extern "C" void mul_G2_pts(uint64_t ctxt,
                           uint8_t *pt1, uint8_t *pt2)
{
  element_t p1, p2;
  int nel;
  element_init_G2(p1, Pairing(ctxt));
  nel = element_length_in_bytes_compressed(p1);
  if (tst_nonzero(pt1, nel))
  {
    if (tst_nonzero(pt2, nel))
    {
      element_init_G2(p2, Pairing(ctxt));
      element_from_bytes_compressed(p1, pt1);
      element_from_bytes_compressed(p2, pt2);
      element_mul(p1, p1, p2);
      element_clear(p2);
      if (element_is0(p1))
        memset(pt1, 0, nel);
      else
        element_to_bytes_compressed(pt1, p1);
    }
  }
  else if (tst_nonzero(pt2, nel))
    memcpy(pt1, pt2, nel);
  element_clear(p1);
}

extern "C" void div_G2_pts(uint64_t ctxt,
                           uint8_t *pt1, uint8_t *pt2)
{
  element_t p1, p2;
  int nel;
  element_init_G2(p1, Pairing(ctxt));
  nel = element_length_in_bytes_compressed(p1);
  if (tst_nonzero(pt1, nel))
  {
    if (tst_nonzero(pt2, nel))
    {
      element_init_G2(p2, Pairing(ctxt));
      element_from_bytes_compressed(p1, pt1);
      element_from_bytes_compressed(p2, pt2);
      element_div(p1, p1, p2);
      element_clear(p2);
      if (element_is0(p1))
        memset(pt1, 0, nel);
      else
        element_to_bytes_compressed(pt1, p1);
    }
  }
  else if (tst_nonzero(pt2, nel))
  {
    element_from_bytes_compressed(p1, pt2);
    element_invert(p1, p1);
    element_to_bytes_compressed(pt1, p1);
  }
  element_clear(p1);
}

extern "C" void neg_G2_pt(uint64_t ctxt,
                          uint8_t *pt1)
{
  element_t p1;
  int nel;
  element_init_G2(p1, Pairing(ctxt));
  nel = element_length_in_bytes_compressed(p1);
  if (tst_nonzero(pt1, nel))
  {
    element_from_bytes_compressed(p1, pt1);
    element_neg(p1, p1);
    element_to_bytes_compressed(pt1, p1);
  }
  element_clear(p1);
}

extern "C" void inv_G2_pt(uint64_t ctxt,
                          uint8_t *pt1)
{
  element_t p1;
  int nel;
  element_init_G2(p1, Pairing(ctxt));
  nel = element_length_in_bytes_compressed(p1);
  if (tst_nonzero(pt1, nel))
  {
    element_from_bytes_compressed(p1, pt1);
    element_invert(p1, p1);
    element_to_bytes_compressed(pt1, p1);
  }
  element_clear(p1);
}

// ----------------------------------------------

extern "C" void add_Zr_vals(uint64_t ctxt,
                            uint8_t *zr1, uint8_t *zr2)
{
  element_t z1, z2;
  element_init_Zr(z1, Pairing(ctxt));
  element_init_Zr(z2, Pairing(ctxt));
  element_from_bytes(z1, zr1);
  element_from_bytes(z2, zr2);
  element_add(z1, z1, z2);
  element_to_bytes(zr1, z1);
  element_clear(z1);
  element_clear(z2);
}

extern "C" void sub_Zr_vals(uint64_t ctxt,
                            uint8_t *zr1, uint8_t *zr2)
{
  element_t z1, z2;
  element_init_Zr(z1, Pairing(ctxt));
  element_init_Zr(z2, Pairing(ctxt));
  element_from_bytes(z1, zr1);
  element_from_bytes(z2, zr2);
  element_sub(z1, z1, z2);
  element_to_bytes(zr1, z1);
  element_clear(z1);
  element_clear(z2);
}

extern "C" void mul_Zr_vals(uint64_t ctxt,
                            uint8_t *zr1, uint8_t *zr2)
{
  element_t z1, z2;
  element_init_Zr(z1, Pairing(ctxt));
  element_init_Zr(z2, Pairing(ctxt));
  element_from_bytes(z1, zr1);
  element_from_bytes(z2, zr2);
  element_mul(z1, z1, z2);
  element_to_bytes(zr1, z1);
  element_clear(z1);
  element_clear(z2);
}

/*
  Sets x = a * b.
  b should be a valid decimal string.
*/
extern "C" void mul_Zr_mpz(uint64_t ctxt, uint8_t *x, 
                          uint8_t *z, const uint8_t *b)
{
  mpz_t n;
  mpz_init(n);
  mpz_set_str(n, (char *) b, 10);

  element_t zr, ans;
  
  element_init_Zr(zr, Pairing(ctxt));
  element_init_Zr(ans, Pairing(ctxt));
  element_from_bytes(zr, z);
  element_mul_mpz(ans, zr, n);
  element_to_bytes(x, ans);

  mpz_clear(n);
  element_clear(zr);
  element_clear(ans);
}

extern "C" void div_Zr_vals(uint64_t ctxt,
                            uint8_t *zr1, uint8_t *zr2)
{
  element_t z1, z2;
  element_init_Zr(z1, Pairing(ctxt));
  element_init_Zr(z2, Pairing(ctxt));
  element_from_bytes(z1, zr1);
  element_from_bytes(z2, zr2);
  element_div(z1, z1, z2);
  element_to_bytes(zr1, z1);
  element_clear(z1);
  element_clear(z2);
}

extern "C" void exp_Zr_vals(uint64_t ctxt,
                            uint8_t *zr1, uint8_t *zr2)
{
  element_t z1, z2;
  element_init_Zr(z1, Pairing(ctxt));
  element_init_Zr(z2, Pairing(ctxt));
  element_from_bytes(z1, zr1);
  element_from_bytes(z2, zr2);
  element_pow_zn(z1, z1, z2);
  element_to_bytes(zr1, z1);
  element_clear(z1);
  element_clear(z2);
}

extern "C" void inv_Zr_val(uint64_t ctxt,
                           uint8_t *zr)
{
  element_t z;
  int nel;
  element_init_Zr(z, Pairing(ctxt));
  nel = element_length_in_bytes(z);
  if (tst_nonzero(zr, nel))
  {
    element_from_bytes(z, zr);
    element_invert(z, z);
    element_to_bytes(zr, z);
  }
  element_clear(z);
}

extern "C" void neg_Zr_val(uint64_t ctxt,
                           uint8_t *zr)
{
  element_t z;
  int nel;
  element_init_Zr(z, Pairing(ctxt));
  nel = element_length_in_bytes(z);
  if (tst_nonzero(zr, nel))
  {
    element_from_bytes(z, zr);
    element_neg(z, z);
    element_to_bytes(zr, z);
  }
  element_clear(z);
}

// ----------------------------------------------

extern "C" void mul_G1z(uint64_t ctxt,
                        uint8_t *g1, uint8_t *zr)
{
  element_t z, g;
  int nelg, nelz;

  element_init_G1(g, Pairing(ctxt));
  nelg = element_length_in_bytes_compressed(g);
  if (tst_nonzero(g1, nelg))
  {
    element_init_Zr(z, Pairing(ctxt));
    nelz = element_length_in_bytes(z);
    if (tst_nonzero(zr, nelz))
    {
      element_from_bytes(z, zr);
      element_from_bytes_compressed(g, g1);
      element_mul_zn(g, g, z);
      if (element_is0(g))
        memset(g1, 0, nelg);
      else
        element_to_bytes_compressed(g1, g);
    }
    else
      memset(g1, 0, nelg);
    element_clear(z);
  }
  element_clear(g);
}

extern "C" void exp_G1z(uint64_t ctxt,
                        uint8_t *g1, uint8_t *zr)
{
  element_t z, g;
  int nelg, nelz;

  element_init_G1(g, Pairing(ctxt));
  nelg = element_length_in_bytes_compressed(g);
  if (tst_nonzero(g1, nelg))
  {
    element_init_Zr(z, Pairing(ctxt));
    nelz = element_length_in_bytes(z);
    if (tst_nonzero(zr, nelz))
    {
      element_from_bytes(z, zr);
      element_from_bytes_compressed(g, g1);
      element_pow_zn(g, g, z);
      if (element_is0(g))
        memset(g1, 0, nelg);
      else
        element_to_bytes_compressed(g1, g);
    }
    else
      memset(g1, 0, nelg);
    element_clear(z);
  }
  element_clear(g);
}


/*
  Sets x = g1^n, thit is g1 times g1 times ... times g1 where there are n g1's.
  n should be a valid decimal string.
*/
extern "C" void exp_G1_mpz(uint64_t ctxt, uint8_t *x, 
                          uint8_t *g1, const uint8_t *n)
{
  mpz_t pow;
  mpz_init(pow);
  mpz_set_str(pow, (char *) n, 10);

  element_t g, ans;
  
  element_init_G1(g, Pairing(ctxt));
  element_init_G1(ans, Pairing(ctxt));
  
  int nelg = element_length_in_bytes_compressed(g);
  if (tst_nonzero(g1, nelg)) {
    element_from_bytes_compressed(g, g1);
    element_pow_mpz(ans, g, pow);
    if (element_is0(ans))
      memset(x, 0, nelg);
    else
      element_to_bytes_compressed(x, ans);
  }

  mpz_clear(pow);
  element_clear(g);
  element_clear(ans);
}

/*
  Sets x = a * b.
  b should be a valid decimal string.
*/
extern "C" void mul_G1_mpz(uint64_t ctxt, uint8_t *x, 
                          uint8_t *g1, const uint8_t *b)
{
  mpz_t n;
  mpz_init(n);
  mpz_set_str(n, (char *) b, 10);

  element_t g, ans;
  
  element_init_G1(g, Pairing(ctxt));
  element_init_G1(ans, Pairing(ctxt));
  
  int nelg = element_length_in_bytes_compressed(g);
  if (tst_nonzero(g1, nelg)) {
    element_from_bytes_compressed(g, g1);
    element_mul_mpz(ans, g, n);
    if (element_is0(ans))
      memset(x, 0, nelg);
    else
      element_to_bytes_compressed(x, ans);
  }

  mpz_clear(n);
  element_clear(g);
  element_clear(ans);
}

// ----------------------------------------------

extern "C" void mul_G2z(uint64_t ctxt,
                        uint8_t *g1, uint8_t *zr)
{
  element_t z, g;
  int nelg, nelz;

  element_init_G2(g, Pairing(ctxt));
  nelg = element_length_in_bytes_compressed(g);
  if (tst_nonzero(g1, nelg))
  {
    element_init_Zr(z, Pairing(ctxt));
    nelz = element_length_in_bytes(z);
    if (tst_nonzero(zr, nelz))
    {
      element_from_bytes(z, zr);
      element_from_bytes_compressed(g, g1);
      element_mul_zn(g, g, z);
      if (element_is0(g))
        memset(g1, 0, nelg);
      else
        element_to_bytes_compressed(g1, g);
    }
    else
      memset(g1, 0, nelg);
    element_clear(z);
  }
  element_clear(g);
}

extern "C" void exp_G2z(uint64_t ctxt,
                        uint8_t *g1, uint8_t *zr)
{
  element_t z, g;
  int nelg, nelz;

  element_init_G2(g, Pairing(ctxt));
  nelg = element_length_in_bytes_compressed(g);
  if (tst_nonzero(g1, nelg))
  {
    element_init_Zr(z, Pairing(ctxt));
    nelz = element_length_in_bytes(z);
    if (tst_nonzero(zr, nelz))
    {
      element_from_bytes(z, zr);
      element_from_bytes_compressed(g, g1);
      element_pow_zn(g, g, z);
      if (element_is0(g))
        memset(g1, 0, nelg);
      else
        element_to_bytes_compressed(g1, g);
    }
    else
      memset(g1, 0, nelg);
    element_clear(z);
  }
  element_clear(g);
}

// ----------------------------------------------

extern "C" void mul_GT_vals(uint64_t ctxt,
                            uint8_t *gt1, uint8_t *gt2)
{
  element_t z1, z2;
  int nel;
  element_init_GT(z1, Pairing(ctxt));
  nel = element_length_in_bytes(z1);
  if (tst_nonzero(gt1, nel))
  {
    if (tst_nonzero(gt2, nel))
    {
      element_init_GT(z2, Pairing(ctxt));
      element_from_bytes(z1, gt1);
      element_from_bytes(z2, gt2);
      element_mul(z1, z1, z2);
      element_clear(z2);
      if (element_is0(z1))
        memset(gt1, 0, nel);
      else
        element_to_bytes(gt1, z1);
    }
    else
      memset(gt1, 0, nel);
  }
  element_clear(z1);
}

extern "C" void div_GT_vals(uint64_t ctxt,
                            uint8_t *gt1, uint8_t *gt2)
{
  element_t z1, z2;
  int nel;

  element_init_GT(z1, Pairing(ctxt));
  nel = element_length_in_bytes(z1);
  if (tst_nonzero(gt1, nel))
  {
    if (tst_nonzero(gt2, nel))
    {
      element_init_GT(z2, Pairing(ctxt));
      element_from_bytes(z1, gt1);
      element_from_bytes(z2, gt2);
      element_div(z1, z1, z2);
      element_clear(z2);
      if (element_is0(z1))
        memset(gt1, 0, nel);
      else
        element_to_bytes(gt1, z1);
    }
    else
      memset(gt1, 0, nel);
  }
  element_clear(z1);
}

extern "C" void inv_GT_val(uint64_t ctxt,
                           uint8_t *gt)
{
  element_t z1;
  int nel;

  element_init_GT(z1, Pairing(ctxt));
  nel = element_length_in_bytes(z1);
  if (tst_nonzero(gt, nel))
  {
    element_from_bytes(z1, gt);
    element_invert(z1, z1);
    element_to_bytes(gt, z1);
  }
  element_clear(z1);
}

extern "C" void exp_GTz(uint64_t ctxt,
                        uint8_t *gt, uint8_t *zr)
{
  element_t z1, z2;
  int nelg, nelz;

  element_init_GT(z1, Pairing(ctxt));
  nelg = element_length_in_bytes(z1);
  if (tst_nonzero(gt, nelg))
  {
    element_init_Zr(z2, Pairing(ctxt));
    nelz = element_length_in_bytes(z2);
    if (tst_nonzero(zr, nelz))
    {
      element_from_bytes(z1, gt);
      element_from_bytes(z2, zr);
      element_pow_zn(z1, z1, z2);
      if (element_is0(z1))
        memset(gt, 0, nelg);
      else
        element_to_bytes(gt, z1);
    }
    else
      memset(gt, 0, nelg);
    element_clear(z2);
  }
  element_clear(z1);
}

// ----------------------------------------------

extern "C" void get_G1_from_hash(uint64_t ctxt,
                                 uint8_t *g1_pt, uint8_t *phash, uint64_t nhash)
{
  element_t g;

  element_init_G1(g, Pairing(ctxt));
  element_from_hash(g, phash, nhash);
  element_to_bytes_compressed(g1_pt, g);
  element_clear(g);
}

extern "C" void get_G1_from_byte(uint64_t ctxt,
                                 uint8_t *g1_pt, uint8_t *pbyte)
{
  element_t g1;

  element_init_G1(g1, Pairing(ctxt));
  element_from_bytes_compressed(g1, pbyte);
  element_to_bytes_compressed(g1_pt, g1);
  element_clear(g1);
}

//extern "C" void get_byte_from_element(uint8_t *el_pt, char *pbyte)
//{
//  element_to_bytes(pbyte,el_pt);
//}

extern "C" void get_G2_from_hash(uint64_t ctxt,
                                 uint8_t *g2_pt, uint8_t *phash, uint64_t nhash)
{
  element_t g;

  element_init_G2(g, Pairing(ctxt));
  element_from_hash(g, phash, nhash);
  element_to_bytes_compressed(g2_pt, g);
  element_clear(g);
}

extern "C" void get_G2_from_byte(uint64_t ctxt,
                                 uint8_t *g2_pt, uint8_t *pbyte)
{
  element_t g2;

  element_init_G2(g2, Pairing(ctxt));
  element_from_bytes_compressed(g2, pbyte);
  element_to_bytes_compressed(g2_pt, g2);
  element_clear(g2);
}

extern "C" void get_Zr_from_hash(uint64_t ctxt,
                                 uint8_t *zr_val, uint8_t *phash, uint64_t nhash)
{
  element_t z;

  element_init_Zr(z, Pairing(ctxt));
  element_from_hash(z, phash, nhash);
  element_to_bytes(zr_val, z);
  element_clear(z);
}

extern "C" void get_Zr_from_byte(uint64_t ctxt,
                                 uint8_t *zr_pt, uint8_t *pbyte)
{
  element_t z;

  element_init_Zr(z, Pairing(ctxt));
  element_from_bytes(z, pbyte);
  element_to_bytes(zr_pt, z);
  element_clear(z);
}

extern "C" void init_Zr(uint64_t ctxt, char *param_str, uint64_t nel)
{
  int64_t ans = -1;

    if (IsZrInit(ctxt))
    {
      element_clear(zr_gen(ctxt));
      pairing_clear(zr_Pairing(ctxt));
      IsZrInit(ctxt) = false;
    }
    ans = pairing_init_set_buf(zr_Pairing(ctxt), param_str, nel);
    if (0 == ans)
    {

      element_init_Zr(zr_gen(ctxt), zr_Pairing(ctxt));
      element_random(zr_gen(ctxt));

      IsZrInit(ctxt) = true;
    }
}

extern "C" uint64_t get_Zr(uint64_t ctxt,uint8_t *pbuf, uint64_t buflen)
{
  return get_datum(zr_gen(ctxt), pbuf, buflen);
}

//
extern "C" int64_t validate_bilinearity(uint64_t ctxt, uint8_t *g1_a, 
                          uint8_t *g1_b, uint8_t *g1_x, uint8_t *g2_y) {
  
  element_t ptG1A, ptG1B, ptG1X, ptG2Y, pair1, pair2;
  
  element_init_G1(ptG1A, Pairing(ctxt));
  element_init_G1(ptG1B, Pairing(ctxt));
  element_init_G1(ptG1X, Pairing(ctxt));
  element_init_G2(ptG2Y, Pairing(ctxt));
  element_init_GT(pair1, Pairing(ctxt));
  element_init_GT(pair2, Pairing(ctxt));

  element_from_bytes(ptG1A, g1_a);
  element_from_bytes(ptG1B, g1_b);
  element_from_bytes(ptG1X, g1_x);
  element_from_bytes(ptG2Y, g2_y);

  pairing_apply(pair1, ptG1A, ptG1B, Pairing(ctxt));
  pairing_apply(pair2, ptG1X, ptG2Y, Pairing(ctxt));
  int result = element_cmp(pair1, pair2);

  element_clear(ptG1A);
  element_clear(ptG1B);
  element_clear(ptG1X);
  element_clear(ptG2Y);
  element_clear(pair1);
  element_clear(pair2);

  return result;
}

// -- end of pbc_intf.cpp -- //
