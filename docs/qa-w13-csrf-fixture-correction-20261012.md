# W13 checked CSV identity test fixture correction (local evidence)

Issue #1197. Parent W13 branch head: `bbc53fb21364de1cb8957bbd5b2b2ca0de04dd0a`.

The original W13 positive fixture supplied a null CSRF token despite the stored session having a valid CSRF value. Its positive assertion therefore fails under the later canonical session tuple check for a reason unrelated to the intended pre-render identity regression. Correct the four `AuthState` constructors to use the persisted CSRF value (or a nonempty synthetic value for the unknown token). This preserves the expected-RED pre-render checks while making the valid-session positive control meaningful.

Corrected test file Git blob: `0e72531f9132afc5adfe1c4682ff8d636589e41c`; SHA-256: `c96e416938ae424ed9b55c699c5310adc22c1c273d76f011e9624ee60c6476a6`.

Offline isolated fixture contract: 5/5 passing on Python, plus syntax compilation. This is not full repository WSGI CI and not proof that the default web export is protected. The attempted test-file update was refused by connector safety checks, so the correction has NOT been committed. No merge or deployment; M3/M7 PLAN/LAB only.
