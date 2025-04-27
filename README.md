# Cool_Delivery_Deployment

To ensure an efficient and reproducible deployment of the Secure Cloud Architecture frontend, we opted for a Docker-based delivery combined with a GitHub repository.


# Deployment Instructions

To deploy the frontend locally or in a server environment:

<pre class="overflow-visible!" data-start="1921" data-end="2201"><div class="contain-inline-size rounded-md border-[0.5px] border-token-border-medium relative bg-token-sidebar-surface-primary"></div></pre>


## Clone the repository

git clone https://github.com/`<your-github-username>`/secure-cloud-frontend.git
cd secure-cloud-frontend

## Build the Docker image

docker build -t cool-delivery-frontend .

## Run the Docker container

docker run -d -p 8080:80 cool-delivery-frontend



## The static website will then be accessible at:

http://localhost:8080
