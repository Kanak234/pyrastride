# Third-Party Notices

PyraStride reuses a small, clearly-bounded portion of third-party code. That
code, its author, its license, and exactly what was reused are recorded here.
Its license text is preserved in this repository.

---

## stride-gpt

- **Upstream:** https://github.com/mrwadams/stride-gpt
- **Author / copyright holder:** Copyright (c) 2024 Matt Adams
- **License:** MIT (full text preserved in [`LICENSE.stride-gpt`](LICENSE.stride-gpt))
- **What was reused:** the SARIF ruleId-sanitisation and message-bounding logic,
  adapted into [`pyrastride/sarif_helpers.py`](pyrastride/sarif_helpers.py) as
  `make_sarif_rule_id` and `sarif_text`. Upstream defines these as
  `_make_sarif_rule_id` and `_sarif_text` in `stride_gpt/agent/report.py`. The
  functions are largely verbatim; `make_sarif_rule_id` was generalised to accept
  the namespace prefix as a parameter (upstream hard-codes `STRIDE/`).
- **What was NOT taken:** stride-gpt's LLM threat-modelling engine, its Streamlit
  UI, its agent/report pipeline, its prompts, its data model, and everything
  else. PyraStride does not call an LLM and shares none of that code.

Under the MIT license this reuse is permitted provided the copyright notice and
license text are retained, which they are (`LICENSE.stride-gpt`). PyraStride
does not represent any stride-gpt code as original: the two reused functions
carry an in-file provenance header, and this file records the source.

---

## Relationship to PyraSec

PyraStride is designed to consume the SARIF output of **PyraSec**, the author's
own static security scanner. PyraSec is a separate project by the same author
and is not third-party; it is named here only to explain what PyraStride
ingests.
