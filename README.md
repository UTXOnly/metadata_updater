# Nostr Metadata Updater

The Nostr Metadata Updater is a containerized web application powered by `FastAPI` and `asyncio`. It queries and updates metadata on Nostr relays in real-time. The app checks for outdated events (kind 0) on various relays and rebroadcasts the latest metadata to those relays found to have outdated events.

This application leverages `FastAPI` to provide a web-based interface and uses `asyncio` to handle asynchronous queries to the relays, ensuring high performance and responsiveness.

![image](https://github.com/user-attachments/assets/1259ee9a-82a5-4522-a36e-9181ac8a89e1)


## Features

- Queries online Nostr relays for events.
- Identifies relays with outdated events.
- Rebroadcasts the latest event to relays with outdated events.


## Requirements

- [Docker](https://docs.docker.com/get-docker/)

## Build and Run

Clone the repository:

```bash
git clone https://github.com/UTXOnly/metadata_updater.git
cd metadata_updater
```

### Build the Docker image:

```bash
docker build -t nostr-metadata-updater .
```
### Run the Docker container:

```bash
docker run -d --name metadata-updater -p 8000:8000 nostr-metadata-updater
```

The application will run in the background, exposing the FastAPI web application on http://localhost:8000.

### Troubleshooting
If you encounter any issues, you can inspect the container logs to see any errors or warnings:

#### Check the container logs:

```bash
docker logs metadata-updater
```
To view real-time logs, use the following command:

```bash
docker logs -f metadata-updater
```

#### Stopping and Cleaning Up

To stop and clean up the container:

##### Stop the container:

```bash
docker stop metadata-updater
```
Remove the container:

```bash
docker rm metadata-updater
```
**Optional: Remove the Docker image if you want to clean up all images and start fresh:**

```bash
docker rmi nostr-metadata-updater
```