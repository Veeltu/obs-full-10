# Dedykowany serwis LoadBalancer dla syslog TCP na port 54536
resource "kubernetes_service_v1" "remote_syslog" {
  metadata {
    name      = "remote-syslog-1"
    namespace = kubernetes_namespace.network.metadata[0].name
    
    annotations = {
      # External DNS utworzy rekord DNS na podstawie tej adnotacji
      "external-dns.alpha.kubernetes.io/hostname" = "network.observability.test.pndrs.de"
      # Opcjonalnie: określ TTL rekordu DNS
      "external-dns.alpha.kubernetes.io/ttl" = "300"
    }
    
    labels = {
      app       = "opentelemetry"
      component = "remote-syslog"
      purpose   = "syslog-ingress"
    }
  }

  spec {
    type = "LoadBalancer"
    
    selector = {
      app       = "opentelemetry"
      component = "otel-collector"
    }

    port {
      name        = "syslog-tcp-rfc6587"
      port        = 54526        
      target_port = 54526       
      protocol    = "TCP"
    }

    port {
      name        = "syslog-tcp-rfc5424"
      port        = 55551        
      target_port = 54536       
      protocol    = "TCP"
    }

    port {
      name        = "snmp-trap"
      port        = 162        
      target_port = 162       
      protocol    = "UDP"
    }
  }
}