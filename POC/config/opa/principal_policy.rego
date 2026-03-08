# Principal role resolution based on SPIFFE ID path prefix.
# Level 0 (system) has highest authority, Level 5 (anonymous) has lowest.

package precinct.principal

import rego.v1

default principal_level := 5
default principal_role := "anonymous"

principal_level := 0 if { startswith(input.spiffe_id, concat("", ["spiffe://", input.trust_domain, "/system/"])) }
principal_level := 1 if { startswith(input.spiffe_id, concat("", ["spiffe://", input.trust_domain, "/owner/"])) }
principal_level := 2 if { startswith(input.spiffe_id, concat("", ["spiffe://", input.trust_domain, "/delegated/"])) }
principal_level := 3 if { startswith(input.spiffe_id, concat("", ["spiffe://", input.trust_domain, "/agents/"])) }
principal_level := 4 if { startswith(input.spiffe_id, concat("", ["spiffe://", input.trust_domain, "/external/"])) }

principal_role := "system" if { principal_level == 0 }
principal_role := "owner" if { principal_level == 1 }
principal_role := "delegated_admin" if { principal_level == 2 }
principal_role := "agent" if { principal_level == 3 }
principal_role := "external_user" if { principal_level == 4 }

# deny if caller level exceeds the required level threshold
deny_insufficient_level if {
    input.required_level != null
    principal_level > input.required_level
}
