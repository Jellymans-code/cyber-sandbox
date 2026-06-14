import docker
import time
import sys

def main():
    print("Connecting to Docker engine...")
    try:
        client = docker.from_env()
    except Exception as e:
        print(f"Failed to connect to Docker: {e}")
        sys.exit(1)

    print("Configuring isolated sandbox environment...")
    try:
        container =  client.containers.create(
            image = "alpine",
            command = ["sleep", "5"],
            network_mode = "none",
            mem_limit= "64m",
            nano_cpus = 500000000
        )
    except Exception as e:
        print(f"Failed to create container: {e}")
        sys.exit(1)

    def cleanup():
        print("Cleaning up sandbox environment...")
        try:
            container.remove(force = True)
            print("Sandbox demolished successfully")
        except Exception:
            pass
    
    print("Booting up the container...")
    container.start()
    print(f"Container {container.short_id} is now alive")
    print("Waiting for sandbox execution to complete...")
    while True:
        container.reload()
        if container.status == "exited":
            break
        time.sleep(0.5)

    print("Container finished its lifecycle and exited safely")

    cleanup()

if __name__ == "__main__":
    main()


