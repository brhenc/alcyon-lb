# Quiet measurement, 2026-10-25 04:40 (whole memory series)

How it was run:
- The supervisor ran `/tmp/q-measure.sh` under `flock -x /tmp/ibex-load.lock`, during a window
  agreed with depeche-session: llama-server was stopped (state `T`) and the governor was
  `performance`.
- Each line is the output of `tools/measure/insreq.sh <label> <bin> <scenario> <client> 30000 5`:
  instructions:u per request, 5 rounds, sorted with the min first.
- `base` is main 0b57eabf (S1-S4), a release build. `main` is ac694b18 (S5, S7, T459 and T465 on
  top), also a release build. They were interleaved, two rounds each.

```
start 04:40:23 load=3.40 3.48 8.01 llama=Tl gov=performance
base1-keepalive: 49398 49445 49445 49445 49451
base1-rules:     96242 96361 96361 96361 96366
main1-keepalive: 49233 49281 49281 49281 49287
main1-rules:     80483 80589 80589 80589 80594
base2-keepalive: 49406 49445 49445 49445 49451
base2-rules:     96241 96361 96361 96361 96366
main2-keepalive: 49234 49281 49281 49281 49287
main2-rules:     80489 80589 80589 80589 80594
base1-tls:       55548 55623 55623 55625 55631   (client ab1s, scenarios/tls.body)
main1-tls:       55376 55447 55447 55449 55455
base2-tls:       55552 55623 55623 55625 55631
main2-tls:       55367 55447 55447 55449 55455
end 04:42:44 load=1.52 2.73 7.09
```

The same method was used earlier that night, with the results in the merge messages:
- **S1:** 05ddac2e, against d48d6037, with `tune.alcyon.zero-buffers off` on both sides.
- **S2+S3:** fcab8c91, against 05ddac2e.
- **S4:** 0b57eabf, against S3 4ed7312a.
