import matplotlib.pyplot as plt

file_path = "packet_sizes.txt"
try:
    with open(file_path, "r") as file:
        packet_sizes = [int(line.strip()) for line in file.readlines()]
except FileNotFoundError:
    print(f"Error: {file_path} not found. Make sure the C++ program has run first.")
    exit(1)
plt.figure(figsize=(12, 7))
plt.hist(packet_sizes, bins=15, edgecolor="black", alpha=0.6)
plt.title("Packet Size Distribution")
plt.xlabel("Packet Size (bytes)")
plt.ylabel("Frequency")
plt.grid(axis="y", linestyle="--", alpha=0.6)
plt.savefig("packet_histogram.png")
print("Histogram saved as 'packet_histogram.png'")
plt.show()
