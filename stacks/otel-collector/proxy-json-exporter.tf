resource "kubernetes_config_map" "proxy_config" {
  metadata {
    name      = "proxy-config"
    namespace = "network"
  }
  data = {
    "config.yaml" = file("proxy-json-exporter-config.yaml")
  }
}

resource "kubernetes_deployment" "proxy_json_exporter" {
  metadata {
    name      = "proxy-json-exporter"
    namespace = "network"
    labels = {
      app = "proxy-json-exporter"
    }
  }
  spec {
    replicas = 1
    selector {
      match_labels = {
        app = "proxy-json-exporter"
      }
    }
    template {
      metadata {
        labels = {
          app = "proxy-json-exporter"
        }
      }
      spec {
        container {
          name  = "proxy-json-exporter"
          # image = "veeltu/json-proxy-ver-1.0.12r"
          image = "veeltu/json-proxy-ver-2.20:latest"

          port {
            container_port = 5000
          }

          env {
            name = "PROXYJSON_USERNAME"
            value_from {
              secret_key_ref {
                name = "proxy-json-exporter-credentials"
                key  = "username"
              }
            }
          }

          env {
            name = "PROXYJSON_PASSWORD"
            value_from {
              secret_key_ref {
                name = "proxy-json-exporter-credentials"
                key  = "password"
              }
            }
          }

          # volume_mount {
          #   name       = "proxy-config"
          #   mount_path = "/config"
          #   read_only  = true
          # }

          volume_mount {
            name       = "proxy-config-2"
            mount_path = "/config/config.yaml"
            sub_path   = "config.yaml"
            read_only  = true
          }

        }

        volume {
          name = "proxy-config-2"
          config_map {
            name = kubernetes_config_map.proxy_config.metadata[0].name
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "proxy_json_exporter" {
  metadata {
    name      = "proxy-json-exporter"
    namespace = "network"
  }
  spec {
    selector = {
      app = "proxy-json-exporter"
    }
    port {
      name        = "http"
      port        = 5000
      target_port = 5000
      protocol    = "TCP"
    }
  }
}
