# Bharat AI-SoC — RT2 Explainable AI Verification Report

**Verification date:** 2026-10-22
**Stage:** RT2 — Explainable AI for Network Alerts
**Overall status:** PASS WITH BLOCKER

## 1. Verified Results

| Check | Result | Evidence |
|---|---|---|
| Frontend TypeScript and Vite build | PASS | Production build completed successfully |
| Backend startup | PASS | Uvicorn started on 127.0.0.1:8000 |
| API specification | PASS | OpenAPI document returned API metadata |
| Backend health endpoint | PASS | /api/v1/health returned status healthy |
| Network IDS unavailable-state handling | PASS | Endpoint returned the expected unavailable response |
| Explainable AI interface | IMPLEMENTED, MODEL UNAVAILABLE | UI reports that the frozen model and explanation pipeline are not integrated |

## 2. Confirmed Backend Status

- Advisory engine: rule_based_active
- Network IDS: unavailable; frozen 79-feature model integration pending
- URL phishing detector: unavailable; model integration pending
- SMS scam detector: unavailable; model integration pending
- Llama runtime: not verified; disabled by backend configuration

## 3. Network IDS Endpoint Verification

Endpoint tested:

POST /api/v1/threats/analyze-pcap

Observed response:

Network IDS detector is unavailable. The frozen 79-feature Network IDS pipeline has not been integrated. Arbitrary file upload/execution is prohibited.

This response is consistent with the reported detector status. No successful model inference was demonstrated.

## 4. Explainable AI Requirements

The interface is designed to display:

- The actual model prediction and confidence.
- The top three supported feature contributions.
- Contribution strength calculated by the selected explanation method.
- A plain-language explanation of the prediction.

These results must only be displayed when actual model evidence is available.

## 5. Outstanding Blockers

1. Obtain and integrate the frozen 79-feature Network IDS model.
2. Integrate its matching feature-extraction pipeline.
3. Verify that the extracted feature order, names, and preprocessing match the model.
4. Generate predictions from real test inputs.
5. Calculate and validate feature contributions for individual predictions.
6. Verify the explanations against model outputs and display them in the frontend.
7. Test valid, invalid, and unsupported network-capture inputs end to end.

## 6. Acceptance Decision

**Decision: PASS WITH BLOCKER**

The frontend build, backend startup, health endpoint, and unavailable-detector response were verified.

The complete RT2 Explainable AI feature is NOT accepted as operational because genuine model inference and feature contributions remain unavailable.

No fabricated feature values or model predictions are accepted as evidence.

## 7. Scope and Limitations

This report records the command outputs observed during the verification session. It does not claim that the missing model integration, real-time detection, or actual feature attribution has been completed.
