/* Ppmd8Enc.c -- PPMdI encoder, ANSI C89 Info-ZIP adaptation.
 * Derived from public-domain 7-Zip 26.03 commit 0766b73.
 */
#include "ppmd8.h"

#define kTop ((UInt32)1 << 24)
#define kBot ((UInt32)1 << 15)
#define WRITE_BYTE(p) IByteOut_Write((p)->Stream.Out, (Byte)((p)->Low >> 24))

void Ppmd8_Flush_RangeEnc(CPpmd8 *p)
{
    unsigned i;
    for (i = 0; i < 4; i++, p->Low <<= 8)
        WRITE_BYTE(p);
}

#define RC_NORM(p) \
    while ((p->Low ^ (p->Low + p->Range)) < kTop || \
      (p->Range < kBot && ((p->Range = (0 - p->Low) & (kBot - 1)), 1))) { \
        WRITE_BYTE(p); p->Range <<= 8; p->Low <<= 8; \
    }
#define RC_NORM_LOCAL(p)
#define RC_NORM_REMOTE(p) RC_NORM(p)
#define R p

static void Ppmd8_RangeEnc_Encode(CPpmd8 *p, UInt32 start,
                                  UInt32 size, UInt32 total)
{
    R->Low += start * (R->Range /= total);
    R->Range *= size;
    RC_NORM_LOCAL(R)
}

#define RC_Encode(start, size, total) \
    Ppmd8_RangeEnc_Encode(p, (start), (size), (total));
#define RC_EncodeFinal(start, size, total) \
    RC_Encode((start), (size), (total)) RC_NORM_REMOTE(p)
#define CTX(ref) ((CPpmd8_Context *)Ppmd8_GetContext(p, (ref)))
#define SUCCESSOR(q) Ppmd_GET_SUCCESSOR(q)
void Ppmd8_UpdateModel(CPpmd8 *p);
#define MASK(sym) ((Byte *)charMask)[sym]

void Ppmd8_EncodeSymbol(CPpmd8 *p, int symbol)
{
    size_t charMask[256 / sizeof(size_t)];

    if (p->MinContext->NumStats != 0) {
        CPpmd_State *s = Ppmd8_GetStats(p, p->MinContext);
        UInt32 sum;
        unsigned i;
        UInt32 summFreq = p->MinContext->Union2.SummFreq;
        PPMD8_CORRECT_SUM_RANGE(p, summFreq)
        if (s->Symbol == symbol) {
            RC_EncodeFinal(0, s->Freq, summFreq)
            p->FoundState = s;
            Ppmd8_Update1_0(p);
            return;
        }
        p->PrevSuccess = 0;
        sum = s->Freq;
        i = p->MinContext->NumStats;
        do {
            if ((++s)->Symbol == symbol) {
                RC_EncodeFinal(sum, s->Freq, summFreq)
                p->FoundState = s;
                Ppmd8_Update1(p);
                return;
            }
            sum += s->Freq;
        } while (--i);
        RC_Encode(sum, summFreq - sum, summFreq)
        PPMD_SetAllBitsIn256Bytes(charMask)
        {
            CPpmd_State *s2 = Ppmd8_GetStats(p, p->MinContext);
            MASK(s->Symbol) = 0;
            do {
                unsigned sym0 = s2[0].Symbol;
                unsigned sym1 = s2[1].Symbol;
                s2 += 2;
                MASK(sym0) = 0;
                MASK(sym1) = 0;
            } while (s2 < s);
        }
    } else {
        UInt16 *prob = Ppmd8_GetBinSumm(p);
        CPpmd_State *s = Ppmd8Context_OneState(p->MinContext);
        UInt32 pr = *prob;
        UInt32 bound = (R->Range >> 14) * pr;
        pr = PPMD_UPDATE_PROB_1(pr);
        if (s->Symbol == symbol) {
            *prob = (UInt16)(pr + (1 << PPMD_INT_BITS));
            R->Range = bound;
            RC_NORM(R)
            {
                unsigned freq = s->Freq;
                CPpmd8_Context *c = CTX(SUCCESSOR(s));
                p->FoundState = s;
                p->PrevSuccess = 1;
                p->RunLength++;
                s->Freq = (Byte)(freq + (freq < 196));
                if (p->OrderFall == 0 && (const Byte *)c >= p->UnitsStart)
                    p->MaxContext = p->MinContext = c;
                else
                    Ppmd8_UpdateModel(p);
            }
            return;
        }
        *prob = (UInt16)pr;
        p->InitEsc = p->ExpEscape[pr >> 10];
        R->Low += bound;
        R->Range = (R->Range & ~((UInt32)PPMD_BIN_SCALE - 1)) - bound;
        RC_NORM_LOCAL(R)
        PPMD_SetAllBitsIn256Bytes(charMask)
        MASK(s->Symbol) = 0;
        p->PrevSuccess = 0;
    }

    for (;;) {
        CPpmd_See *see;
        CPpmd_State *s;
        UInt32 sum, escFreq;
        CPpmd8_Context *mc;
        unsigned i, numMasked;
        RC_NORM_REMOTE(p)
        mc = p->MinContext;
        numMasked = mc->NumStats;
        do {
            p->OrderFall++;
            if (!mc->Suffix)
                return;
            mc = Ppmd8_GetContext(p, mc->Suffix);
        } while (mc->NumStats == numMasked);
        p->MinContext = mc;
        see = Ppmd8_MakeEscFreq(p, numMasked, &escFreq);
        s = Ppmd8_GetStats(p, p->MinContext);
        sum = 0;
        i = (unsigned)p->MinContext->NumStats + 1;
        do {
            unsigned cur = s->Symbol;
            if ((int)cur == symbol) {
                UInt32 low = sum;
                UInt32 freq = s->Freq;
                unsigned num2;
                Ppmd_See_UPDATE(see)
                p->FoundState = s;
                sum += escFreq;
                num2 = i / 2;
                i &= 1;
                sum += freq & (0 - (UInt32)i);
                if (num2 != 0) {
                    s += i;
                    do {
                        unsigned sym0 = s[0].Symbol;
                        unsigned sym1 = s[1].Symbol;
                        s += 2;
                        sum += s[-2].Freq & (unsigned)(MASK(sym0));
                        sum += s[-1].Freq & (unsigned)(MASK(sym1));
                    } while (--num2);
                }
                PPMD8_CORRECT_SUM_RANGE(p, sum)
                RC_EncodeFinal(low, freq, sum)
                Ppmd8_Update2(p);
                return;
            }
            sum += s->Freq & (unsigned)(MASK(cur));
            s++;
        } while (--i);
        {
            UInt32 total = sum + escFreq;
            see->Summ = (UInt16)(see->Summ + total);
            PPMD8_CORRECT_SUM_RANGE(p, total)
            RC_Encode(sum, total - sum, total)
        }
        {
            const CPpmd_State *s2 = Ppmd8_GetStats(p, p->MinContext);
            s--;
            MASK(s->Symbol) = 0;
            do {
                unsigned sym0 = s2[0].Symbol;
                unsigned sym1 = s2[1].Symbol;
                s2 += 2;
                MASK(sym0) = 0;
                MASK(sym1) = 0;
            } while (s2 < s);
        }
    }
}

#undef kTop
#undef kBot
#undef WRITE_BYTE
#undef RC_NORM
#undef RC_NORM_LOCAL
#undef RC_NORM_REMOTE
#undef R
#undef RC_Encode
#undef RC_EncodeFinal
#undef CTX
#undef SUCCESSOR
#undef MASK
