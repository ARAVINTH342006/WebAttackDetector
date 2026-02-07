from locust import HttpUser, task, between


class WebsiteUser(HttpUser):
    
    wait_time = between(1, 2)

    
    @task(3)
    def home(self):
        
        self.client.get("/")

    
    @task(1)
    def api(self):
        
        self.client.get("/api/tasks")
