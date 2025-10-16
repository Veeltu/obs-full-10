resource "kubernetes_config_map" "json_exporter_config" {
  metadata {
    name      = "json-exporter-config"
    namespace = "network"
  }
  data = {
    "config.yaml" = file("json-exporter-config.yaml")
  }
}

resource "kubernetes_deployment" "json_exporter" {
  metadata {
    name      = "json-exporter"
    namespace = "network"
    labels = {
      app = "json-exporter"
    }
  }
  spec {
    replicas = 1
    selector {
      match_labels = {
        app = "json-exporter"
      }
    }
    template {
      metadata {
        labels = {
          app = "json-exporter"
        }
      }
      spec {
        container {
          name  = "json-exporter"
          image = "prometheuscommunity/json-exporter:latest"
          args  = ["--config.file=/config/config.yaml"]
          port {
            container_port = 7979
          }
          volume_mount {
            name       = "config-volume"
            mount_path = "/config"
          }
        }
        volume {
          name = "config-volume"
          config_map {
            name = kubernetes_config_map.json_exporter_config.metadata[0].name
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "json_exporter" {
  metadata {
    name      = "json-exporter"
    namespace = "network"
  }
  spec {
    selector = {
      app = "json-exporter"
    }
    port {
      protocol    = "TCP"
      port        = 7979
      target_port = 7979
    }
    type = "ClusterIP"
  }
}
