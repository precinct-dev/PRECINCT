# Data Source Access Control Policy - OC-4zrf
# Controls which SPIFFE IDs can access which data source URIs.
# Registered data sources require identity-based grants (data.data_source_grants).
# Mutable data sources (mutable_policy != "block_on_change") require admin identity.
# Unregistered external URIs are blocked for high-risk sessions (risk_score > 5).

package precinct.data_source

import rego.v1

default allow := false

# Registered data sources: check identity access via grants
allow if {
    input.data_source.registered == true
    data_source_grant[_]
}

# Unregistered data sources: allow for low-risk sessions
allow if {
    input.data_source.registered == false
    input.session.risk_score <= 5
}

# Data source grants by SPIFFE ID pattern and URI pattern.
# Grants are loaded from data.data_source_grants (YAML data file).
# SPIFFE patterns use "/" separator so that "*" matches one path segment.
# URI patterns use no separator so that "*" matches any suffix (URIs are
# treated as opaque strings for grant matching, not path hierarchies).
data_source_grant[grant] if {
    some grant in data.data_source_grants
    glob.match(grant.spiffe_pattern, ["/"], input.spiffe_id)
    glob.match(grant.uri_pattern, [], input.data_source.uri)
}

# Mutable sources require admin identity (spiffe://poc.local/admin/*)
deny contains "mutable_source_requires_admin" if {
    input.data_source.registered == true
    input.data_source.mutable_policy != "block_on_change"
    not admin_identity
}

admin_identity if {
    startswith(input.spiffe_id, "spiffe://poc.local/admin/")
}

# Unregistered external URIs blocked for high-risk sessions
deny contains "unregistered_high_risk" if {
    input.data_source.registered == false
    input.session.risk_score > 5
}
