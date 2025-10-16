resource "kubernetes_namespace" "network" {
  metadata {
    name = "network"
    labels = {
      shared-gateway-access = "true"
    }
  }

  lifecycle {
    ignore_changes = [
      metadata[0].annotations["cattle.io/status"],
      metadata[0].annotations["lifecycle.cattle.io/create.namespace-auth"],
    ]
  }
}

# Service account for the OpenTelemetry Collector
# This provides the necessary permissions for the collector to access Kubernetes resources
# resource "kubernetes_service_account_v1" "otel_collector" {
#   metadata {
#     name      = "otel-collector"
#     namespace = kubernetes_namespace.network.metadata[0].name
#   }
# }

# ConfigMap containing the OpenTelemetry Collector configuration
# This defines how the collector will receive, process, and export telemetry data
resource "kubernetes_config_map_v1" "collector" {
  metadata {
    name      = "otel-collector-config"
    namespace = kubernetes_namespace.network.metadata[0].name
  }

  data = {
    "config.yaml" = file("otel-config.yaml")
    # Alternative approach using Terraform to generate the config
    # "config.yaml" = yamlencode(local.otel_config)


  }
  depends_on = [kubernetes_namespace.network]
}


# Service definition for the OpenTelemetry Collector
# Exposes the collector's endpoints for receiving telemetry data
resource "kubernetes_service_v1" "collector" {
  metadata {
    name      = "otel-collector"
    namespace = kubernetes_namespace.network.metadata[0].name
    labels = {
      app       = "opentelemetry"
      component = "otel-collector"
    }
  }
  spec {
    selector = {
      component = "otel-collector"
    }

    # Default endpoint for OpenTelemetry gRPC receiver.
    # Used for receiving telemetry data via gRPC protocol
    port {
      port        = 4317
      target_port = 4317
      protocol    = "TCP"
      name        = "otel-grpc"
    }

    # Default endpoint for OpenTelemetry HTTP receiver.
    # Used for receiving telemetry data via HTTP protocol
    port {
      port        = 4318
      target_port = 4318
      protocol    = "TCP"
      name        = "otel-http"
    }

    # Default endpoint for querying metrics.
    # Used for exposing collector's own metrics
    port {
      port        = 8888
      target_port = 8888
      protocol    = "TCP"
      name        = "metrics"
    }

    port {
      port        = 162
      target_port = 162
      protocol    = "UDP"
      name        = "snmp-trap"
    }

    # port {
    #   port        = 54536
    #   target_port = 54536
    #   protocol    = "TCP"
    #   name        = "syslogtcpenvoy"
    # }
    # Dynamic port configuration for additional TCP routes
    # Allows for flexible port configuration based on local.tcpRoutes variable
    dynamic "port" {
      for_each = local.tcpRoutes
      content {
        port        = port.value.port
        target_port = port.value.port
        protocol    = "TCP"
        name        = port.key
      }
    }

    # dynamic "port" {
    #   for_each = local.tcpRoutesPorts
    #   content {
    #     port        = port.value.port
    #     target_port = port.value.port
    #     protocol    = "TCP"
    #     name        = port.key
    #   }
    # }

    # UDP port for syslog receiver
    # Used for receiving syslog messages over UDP


    # port {
    #   port        = 55679
    #   target_port = 55679
    #   protocol    = "TCP"
    #   name        = "zpages"
    # }
  }
}

# Deployment for the OpenTelemetry Collector
# Runs the collector as a centralized deployment (not as a DaemonSet)
resource "kubernetes_deployment_v1" "collector" {
  metadata {
    name      = "otel-collector"
    namespace = kubernetes_namespace.network.metadata[0].name
    labels = {
      app       = "opentelemetry"
      component = "otel-collector"
    }
  }

  spec {
    selector {
      match_labels = {
        app       = "opentelemetry"
        component = "otel-collector"
      }
    }
    min_ready_seconds         = 5
    progress_deadline_seconds = 120
    replicas                  = 1 # Single replica for now, can be increased for production
    template {
      metadata {
        labels = {
          app       = "opentelemetry"
          component = "otel-collector"
        }
      }
      spec {
        container {
          name = "otel-collector"

          # Standard collector image (commented out)
          #image = "${local.docker_repositories.docker_hub}/otel/opentelemetry-collector:latest"
          #command = ["/otelcol", "--config=/conf/otel-collector-config.yaml"]

          # Using the contrib distribution which includes additional components
          # https://opentelemetry.io/docs/collector/distributions/
          image = "${var.docker_repositories.docker_hub}/otel/opentelemetry-collector-contrib:latest"

          # TODO: we will need a custom distro for this for production. https://opentelemetry.io/docs/collector/custom-collector/

          # Mount the configuration file
          volume_mount {
            name       = "otel-collector-config"
            mount_path = "/etc/otelcol-contrib/config.yaml"
            sub_path   = "config.yaml"
            read_only  = true
          }

          # Mount secrets directory for TLS certificates
          volume_mount {
            name       = "secrets"
            mount_path = "/etc/otelcol-contrib/secrets"
            read_only  = true
          }

          # Resource limits and requests for the collector
          # Ensures the collector has enough resources but doesn't consume too much
          resources {
            limits = {
              memory = "8Gi"
            }
            requests = {
              cpu    = "200m"
              memory = "400Mi"
            }
          }

          # Environment variables for the collector
          # MY_POD_IP is used in the configuration to bind to the correct IP
          env {
            name = "MY_POD_IP"
            value_from {
              field_ref {
                field_path = "status.podIP"
              }
            }
          }

          # Kafka credentials for exporting telemetry to Kafka
          env {
            name = "KAFKA_USERNAME"
            value_from {
              secret_key_ref {
                name = "kafka-credentials"
                key  = "username"
              }
            }
          }
          env {
            name = "KAFKA_PASSWORD"
            value_from {
              secret_key_ref {
                name = "kafka-credentials"
                key  = "password"
              }
            }
          }

          # SNMP credentials for monitoring network devices
          env {
            name = "SNMP_AUTH_PASSWORD"
            value_from {
              secret_key_ref {
                name = "snmp-credentials"
                key  = "auth-password"
              }
            }
          }
          env {
            name = "SNMP_PRIVACY_PASSWORD"
            value_from {
              secret_key_ref {
                name = "snmp-credentials"
                key  = "privacy-password"
              }
            }
          }

          # Node name for identifying which node the collector is running on
          env {
            name = "K8S_NODE_NAME"
            value_from {
              field_ref {
                field_path = "spec.nodeName"
              }
            }
          }

          # Port definitions for various receivers
          # TCP port for syslog
          port {
            container_port = 54536
            name           = "syslog-rfc6587"
          }
          port {
            container_port = 162
            name           = "snmp-trap"
            protocol       = "UDP"
          }

          # port {
          #   container_port = 58001
          #   name           = "syslog-tcp"
          # }

          port {
            container_port = 54526
            name           = "syslog-rfc5424"
          }
          # UDP port for syslog
          # port {
          #   container_port = 54527
          #   name           = "syslogudp"
          #   protocol       = "UDP"
          # }
          # TCP port for TLS-encrypted syslog
          # port {
          #   container_port = 54528
          #   name           = "syslogtcptls"
          # }
          # Default endpoint for ZPages (internal debugging)
          # port {
          #   container_port = 55679
          #   name           = "zpages"
          # }
          # Default endpoint for OpenTelemetry receiver
          # port {
          #   container_port = 4317
          #   name           = "otel-grpc"
          # }
          # Default endpoint for Jaeger gRPC receiver
          # port {
          #   container_port = 14250
          #   name           = "jaeger-grpc"
          # }
          # Default endpoint for Jaeger HTTP receiver
          # port {
          #   container_port = 14268
          #   name           = "jaeger-http"
          # }
          # Default endpoint for Zipkin receiver
          port {
            container_port = 9411
            name           = "zipkin"
          }
          # Default endpoint for querying metrics
          port {
            container_port = 8888
            name           = "metrics"
          }
        }

        # Volume for the configuration
        volume {
          name = "otel-collector-config"
          config_map {
            name = "otel-collector-config"
          }
        }

        # Volume for TLS certificates
        # Uses projected volume to combine multiple certificate secrets

        #  - Creates a projected volume that combines TLS secrets for multiple domains.
        #  - For each domain in local.certs, it exposes two files in the container: a certificate and a private key, with appropriate names.
        #  - Allows applications to easily and securely access certificates directly from the container's file system.

        volume {
          name = "secrets"
          projected {
            sources {
              dynamic "secret" {
                for_each = local.certs
                content {
                  name = replace(secret.value, ".", "-")
                  items {
                    key  = "tls.crt"
                    path = "${replace(secret.value, ".", "-")}.crt"
                  }
                  items {
                    key  = "tls.key"
                    path = "${replace(secret.value, ".", "-")}.key"
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  # Ensure certificates are created before the deployment
  # depends_on = [kubernetes_manifest.certs]
}
