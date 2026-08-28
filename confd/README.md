# ConfD control plane

`fastapi_confd` is a standard ConfD **CDB subscription client**. It is not a
packet-path callback and ConfD never calls into a DPDK worker.

```text
OSS/NMS → NETCONF commit → ConfD CDB_RUNNING
                              ↓
                 fastapi_confd CDB subscription socket
                              ↓
                  read one running-config snapshot
                              ↓
             config.yaml.tmp → fsync → atomic rename
                              ↓
                       SIGUSR1 to FastAPI
                              ↓
                    main lcore reload workflow
```

## Build and run

```bash
export CONFD_DIR=/opt/confd
make -C confd

./confd/fastapi_confd \
  --config /absolute/path/config.yaml \
  --pid "$(pidof FastAPI)" \
  --confd-ip 127.0.0.1 \
  --confd-port 4565
```

The daemon subscribes to `/fastapi:fastapi/spi` and `/fastapi:fastapi/dpi`.
After every completed commit it reads `CDB_RUNNING`, emits the full ACL-relevant
SPI/DPI YAML snapshot, then signals the process. A failed read, write, `fsync`,
or rename leaves the prior YAML unchanged. A signal failure leaves the active
DPDK rules unchanged; the new on-disk snapshot remains available for a retry.

`filters` has a management-only `id` key in YANG. It makes each NETCONF list
entry addressable; the key is not emitted to YAML and does not participate in
packet matching.

## ACL workflow

```text
SIGUSR1
  → main lcore consumes reload flag
  → LoadConfig + schema validation
  → CompileRuleTable: YAML rules → rte_acl_rule[] → rte_acl_build()
  → workers stop at a burst boundary
  → publish the validated new rule-table generation
  → resume workers

RX → IPv4 fragment reassembly → flow cache → exact-5-tuple precheck
   → member negative prefilter → rte_acl_classify(batch) → forward/drop
```

The source-of-truth match is the five-tuple rule: protocol, source IPv4,
destination IPv4/CIDR, source port, destination port. `precedence` is lower-is-
higher and `drop_unmatched` determines the default action. Any optimisation
such as FIB, member-set, or exact-tuple cache must verify the complete rule
before it is allowed to return a match.

The current FIB positive shortcut is deliberately disabled: FIB has
destination longest-prefix semantics, which cannot preserve arbitrary ACL group
precedence over the full five-tuple.

## Operational boundary

This subscriber exports the configuration managed by the YANG model. Treat EAL,
NIC, queue, mempool and virtual-device changes as restart-required; changing
them in CDB does not reinitialize an already running DPDK EAL. SPI/DPI rule
changes are the intended hot-reload scope.
