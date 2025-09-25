import json
import matplotlib.pyplot as plt
import numpy as np
import random

# -----------------------------
# Load JSON Files
# -----------------------------
# Authentication processing times (overall per SC device)
with open("auth_processing_times.json", "r") as f:
    auth_times = json.load(f)

# Load device histories JSON (we now track WeightHistory, VoteOutcome, VoteAccuracyHistory, and TrustScoreHistory)
with open("device_histories.json", "r") as f:
    device_histories = json.load(f)

# Load SC results JSON (each record has DeviceUUID, YesVotes, NoVotes, etc.)
with open("sc_results.json", "r") as f:
    sc_results = json.load(f)

# -----------------------------
# Prepare Data for Plotting
# -----------------------------
# For the sample dynamics, randomly select 5 IoT devices from the histories.
device_keys = list(device_histories.keys())
sample_keys = random.sample(device_keys, min(5, len(device_keys)))

# -----------------------------
# Create a Figure with 6 Subplots in a 3x2 Grid (we'll use 5 and disable the 6th)
# -----------------------------
fig, axes = plt.subplots(nrows=3, ncols=2, figsize=(20, 18))
axes = axes.flatten()

# --- Plot 1: Authentication Processing Times ---
# (X-axis: Order of authentication event, Y-axis: Processing time in seconds)
x = np.arange(1, len(auth_times) + 1)
axes[0].plot(x, auth_times, marker='s', linestyle='-', color='m')
axes[0].set_xlabel("Authentication Event Order")
axes[0].set_ylabel("Processing Time (ms)")
axes[0].set_title("Authentication Processing Times\n(Time required for each authentication)")
axes[0].grid(True)

# --- Plot 2: Weight Dynamics for Sample IoT Devices ---
# (X-axis: Authentication round, Y-axis: Device weight)
for key in sample_keys:
    history = device_histories[key]
    rounds = np.arange(1, len(history["WeightHistory"]) + 1)
    axes[1].plot(rounds, history["WeightHistory"], marker='o', label=key)
axes[1].set_xlabel("Authentication Round")
axes[1].set_ylabel("Device Weight (0-100)")
axes[1].set_title("Weight Dynamics for Sample IoT Devices\n(Reputation evolution over successive authentications)")
axes[1].grid(True)
axes[1].legend()

# --- Plot 3: Vote Accuracy Dynamics for Sample IoT Devices ---
# (X-axis: Authentication round, Y-axis: Vote accuracy in percentage)
for key in sample_keys:
    history = device_histories[key]
    if "VoteAccuracyHistory" in history:
        rounds = np.arange(1, len(history["VoteAccuracyHistory"]) + 1)
        axes[2].plot(rounds, history["VoteAccuracyHistory"], marker='o', label=key)
    else:
        print(f"Warning: Device {key} does not have VoteAccuracyHistory data.")
axes[2].set_xlabel("Authentication Round")
axes[2].set_ylabel("Vote Accuracy (%)")
axes[2].set_title("Vote Accuracy Dynamics for Sample IoT Devices\n(Correct votes as a percentage of total votes)")
axes[2].grid(True)
axes[2].legend()

# --- Plot 4: Trust Score Dynamics for Sample IoT Devices ---
# (X-axis: Authentication round, Y-axis: Trust score)
for key in sample_keys:
    history = device_histories[key]
    if "TrustScoreHistory" in history:
        rounds = np.arange(1, len(history["TrustScoreHistory"]) + 1)
        axes[3].plot(rounds, history["TrustScoreHistory"], marker='o', label=key)
    else:
        print(f"Warning: Device {key} does not have TrustScoreHistory data.")
axes[3].set_xlabel("Authentication Round")
axes[3].set_ylabel("Trust Score")
axes[3].set_title("Trust Score Dynamics for Sample IoT Devices\n(Evolution of trust score over time)")
axes[3].grid(True)
axes[3].legend()

# --- Plot 5: SC Device Voting Outcomes ---
# (X-axis: SC Device identifier, Y-axis: Number of votes)
sc_ids = []
yes_votes = []
no_votes = []
for rec in sc_results:
    sc_ids.append(rec["DeviceUUID"])
    yes_votes.append(rec["YesVotes"])
    no_votes.append(rec["NoVotes"])

x_pos = np.arange(len(sc_ids))
width = 0.35  # width of the bars
axes[4].bar(x_pos - width/2, yes_votes, width, color='g', label='Yes Votes')
axes[4].bar(x_pos + width/2, no_votes, width, color='r', label='No Votes')
axes[4].set_xlabel("SC Device (Authentication Event)")
axes[4].set_ylabel("Number of Votes")
axes[4].set_title("SC Device Voting Outcomes\n(Counts of Yes vs No votes per authentication event)")
axes[4].set_xticks(x_pos)
axes[4].set_xticklabels(sc_ids, rotation=45, ha="right")
axes[4].legend()
axes[4].grid(axis='y', linestyle='--')

# --- Plot 6: (Unused) ---
axes[5].axis('off')

plt.tight_layout()
plt.savefig("combined_auth_plots.png")
plt.show()
