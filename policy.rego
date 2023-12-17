package kubernetes.admission

deny[msg] {
	input.request.object.kind == "Deployment"
    input.request.object.metadata.labels["app.kubernetes.io/component"] == "api"
    not input.request.object.metadata.labels["customer-id"]

	msg := "Label customer-id is required for API deployments"
}

deny[msg] {
    namespace := input.request.namespace
    customer_id := input.request.object.metadata.labels["customer-id"]
    not data.kubernetes.namespaces[namespace].metadata.labels["customer-id"] == customer_id

	msg := "Deployment must be created in the matching customer namespace"
}

deny[msg] {
    has_database := { i | data.kubernetes.deployments["customer-1"][i].metadata.labels["app.kubernetes.io/component"] == "database" }
    not count(has_database) > 0
    
    msg := "No database component found"
}

deny[msg] {
    has_frontend := { i | data.kubernetes.deployments["customer-1"][i].metadata.labels["app.kubernetes.io/component"] == "frontend" }
    not count(has_frontend) > 0
    
    msg := "No frontend component found"
}

deny[msg] {
    not data.kubernetes.services["customer-1"]["api-auth-service"].metadata.labels["app.kubernetes.io/part-of"] == "api"
    
    msg := "No API authentication service found"
}
