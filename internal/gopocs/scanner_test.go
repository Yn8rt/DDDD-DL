package gopocs

import "testing"

func TestMatchRulesUsesProductForNonDefaultProtocolPorts(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		product  string
		port     string
		want     string
	}{
		{name: "elasticsearch product on non-default http port", protocol: "http", product: "Elasticsearch REST API", port: "19200", want: "Elasticsearch-Unauth"},
		{name: "zookeeper jute protocol on non-default port", protocol: "jute", product: "Apache ZooKeeper", port: "12181", want: "Zookeeper-Unauth"},
		{name: "mqtt protocol on non-default port", protocol: "mqtt", product: "", port: "1884", want: "MQTT-Unauth"},
		{name: "amqp protocol on non-default port", protocol: "amqp", product: "Advanced Message Queue Protocol", port: "25672", want: "RabbitMQ-Unauth"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchRules(tt.protocol, tt.product, tt.port, false)
			for _, item := range got {
				if item == tt.want {
					return
				}
			}
			t.Fatalf("matchRules(%q, %q, %q) = %v, want %q", tt.protocol, tt.product, tt.port, got, tt.want)
		})
	}
}

func TestMatchRulesDoesNotTreatAllHTTPAsElasticsearch(t *testing.T) {
	got := matchRules("http", "Apache httpd", "8080", false)
	for _, item := range got {
		if item == "Elasticsearch-Unauth" {
			t.Fatalf("plain HTTP service should not trigger Elasticsearch-Unauth: %v", got)
		}
	}
}
