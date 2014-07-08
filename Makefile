PROJECT = tor_dns_tunnel

# options

# CT_SUITES =
# PLT_APPS = crypto asn1 public_key ssl sasl

# dependencies

# DEPS = ranch
# dep_ranch = https://github.com/extend/ranch.git 0.10.0

# TEST_DEPS =

# standard targets

include erlang.mk

check test: tests
