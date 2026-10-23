# Deferred measurement validation

Measurement targets and TCB classification policy are pending for the XCENA RoT
integration. Successful CHALLENGE and KEY_EXCHANGE tests temporarily run only the
NO_MEASUREMENT_SUMMARY_HASH variant. Certificate, signature, session and response
checks in those variants continue to execute.

The integrating application controls the GET_MEASUREMENTS group separately via
its common_test_group_config_t configuration. A deferred group must be reported
as SKIP. This reduced profile does not establish measurement or TCB attestation
correctness and does not change the responder firmware or capability flags.

Restore the TCB_COMPONENT_MEASUREMENT_HASH and ALL_MEASUREMENTS_HASH entries in
both success-test arrays, and enable the application's measurement group, once
measurement classification and expected values have been defined and validated.
