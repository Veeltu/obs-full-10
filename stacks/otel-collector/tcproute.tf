resource "kubernetes_manifest" "syslog_routes" {
  for_each = local.tcpRoutes
  manifest = {
    apiVersion = "gateway.networking.k8s.io/v1alpha2"
    kind       = lookup(each.value, "ssl", { mode = "Terminate" })["mode"] == "Passthrough" ? "TLSRoute" : "TCPRoute"
    metadata = {
      name      = each.key
      namespace = kubernetes_namespace.network.metadata.0.name
    }
    spec = {
      parentRefs = [
        {
          name        = "otel"
          sectionName = each.key
          namespace = "otel-collector"
        }
      ]
      rules = [
        {
          backendRefs = [
            {
              name = kubernetes_service_v1.collector.metadata.0.name
              port = each.value.port
            }
          ]
        }
      ]
    }
  }
}
