; One 64-bit UBFIZ expression: lsb=2, width=61.
; MacIR source form: (x & ((1 << 61) - 1)) << 2.
; Comparison: (x << 2) & 0x7ffffffffffffffc.
; Unsat means no 64-bit x makes these bit-vector forms differ.
(set-logic QF_BV)
(declare-fun x () (_ BitVec 64))
(define-fun macir () (_ BitVec 64)
  (bvshl (bvand x #x1fffffffffffffff) #x0000000000000002))
(define-fun comparison () (_ BitVec 64)
  (bvand (bvshl x #x0000000000000002) #x7ffffffffffffffc))
(assert (not (= macir comparison)))
(check-sat)
