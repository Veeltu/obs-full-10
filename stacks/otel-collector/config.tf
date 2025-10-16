locals {
  # Defines a set of TCP routes for exposing network services through a gateway or proxy.
  # Each route is identified by a key and specifies a port and (optionally) TLS settings.
  tcpRoutes = {
    # Plain TCP syslog listener (no encryption)
    syslogtcp = {
      port = 54526
    }

    # syslogtcp = {
    #   port = 54536
    # }

    # Plain UDP syslog listener (no encryption)
    # syslogudp = {
    #   port = 54527
    # }
    # Example of a gRPC route (currently commented out)
    # otel2grpc = {
    #   port = 14317
    # }
    # Example of an HTTP route (currently commented out)
    # otel2http = {
    #   port = 14318
    # }
    # TCP syslog with TLS in Passthrough mode (TLS is handled by the backend)
    # syslogtcptls = {
    #   port     = 54528
    #   protocol = "TLS"
    #   tls = {
    #     mode = "Passthrough" # TLS traffic is forwarded as-is to the backend
    #   }
    # }
    # TCP syslog with TLS in Terminate mode (TLS is terminated at the gateway/proxy)
    # syslogtcptlst = {
    #   port     = 54529
    #   protocol = "TLS"
    #   tls = {
    #     mode = "Terminate"                          # TLS is decrypted at the gateway/proxy
    #     certificateRefs = [for s in local.certs : { # References Kubernetes secrets with TLS certificates
    #       kind = "Secret"
    #       name = replace(s, ".", "-")
    #     }]
    #   }
    # }
  }

  # New for traefik in NS: network
  tcpRoutesPorts = {
    # Plain TCP syslog listener (no encryption)
    syslog-tcp = {
      port = 58001
    }
    # Plain UDP syslog listener (no encryption)
    # syslogudp = {
    #   port = 54527
    # }
    # Example of a gRPC route (currently commented out)
    # otel2grpc = {
    #   port = 14317
    # }
    # Example of an HTTP route (currently commented out)
    # otel2http = {
    #   port = 14318
    # }
    # TCP syslog with TLS in Passthrough mode (TLS is handled by the backend)
    # syslogtcptls = {
    #   port     = 54528
    #   protocol = "TLS"
    #   tls = {
    #     mode = "Passthrough" # TLS traffic is forwarded as-is to the backend
    #   }
    # }
    # TCP syslog with TLS in Terminate mode (TLS is terminated at the gateway/proxy)
    # syslogtcptlst = {
    #   port     = 54529
    #   protocol = "TLS"
    #   tls = {
    #     mode = "Terminate"                          # TLS is decrypted at the gateway/proxy
    #     certificateRefs = [for s in local.certs : { # References Kubernetes secrets with TLS certificates
    #       kind = "Secret"
    #       name = replace(s, ".", "-")
    #     }]
    #   }
    # }
  }
}


