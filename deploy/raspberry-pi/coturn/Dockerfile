# coturn 4.18.0 without the file capability on the turnserver binary.
#
# The official image puts CAP_NET_BIND_SERVICE=+ep on turnserver so an unprivileged user can bind
# low ports. We listen on 3478, 5349 and 49160-49200 only, so we do not need it; and with the capability
# present the container needs `cap_add: NET_BIND_SERVICE` to start at all (the kernel refuses to
# exec a binary whose file capability is not in the bounding set), which Docker then grants to the
# non-root process too (CapEff 0x400). Stripping it lets us run with `cap_drop: ALL`, no cap_add and
# no-new-privileges.
#
# Pinned by version and digest (the multi-platform digest Dependabot proposed in #47; compare with
# `docker buildx imagetools inspect coturn/coturn:4.18.0`). Dependabot proposes upgrades, and the
# CI coturn job must pass before one is merged.
FROM coturn/coturn:4.18.0@sha256:bbefd3e1fdfdc0d58770fe01b581fd8b00d9f3a5580d00acb77cf719a6bc78e3

USER root
# `setcap -r` if the tool is in the image; otherwise replace the binary with a plain copy (cp does
# not copy the security.capability extended attribute), keeping mode 0755.
RUN set -eu; \
    binary="$(readlink -f "$(command -v turnserver)")"; \
    if command -v setcap >/dev/null 2>&1; then \
        setcap -r "$binary"; \
    else \
        cp "$binary" "$binary.nocap"; \
        chmod 0755 "$binary.nocap"; \
        mv "$binary.nocap" "$binary"; \
    fi; \
    ls -l "$binary"

# Never root. compose.yaml and coturn/test-coturn.sh set the same user, and replace this
# entrypoint with a short start script that joins the secret file to the config in memory and
# then execs turnserver as pid 1 (the secret is never on a command line).
USER 65534:65534
ENTRYPOINT ["turnserver"]
