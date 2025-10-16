# DDoS Detection & Mitigation Dashboard

This project is a web-based application designed to detect and visualize Distributed Denial of Service (DDoS) attacks in real-time. It uses a combination of rule-based, machine learning-based, and honeypot-based detection methods to identify malicious traffic.

## Features

*   **Real-time Traffic Monitoring**: A live dashboard that displays incoming traffic metrics.
*   **Multi-faceted DDoS Detection**:
    *   **Rule-Based**: Flags IPs that exceed a certain request threshold.
    *   **Machine Learning-Based**: Uses a Decision Tree Classifier to predict malicious traffic based on behavioral features.
    *   **Honeypot**: A hidden field in the login form to trap and identify bots.
*   **Detailed Visualization**: Graphs and charts to visualize attack patterns, including traffic over time and top attacking IPs.
*   **Simulated Environment**: Includes a "real website" and traffic simulation scripts to generate data for testing and demonstration.
*   **Log Export**: Ability to export captured traffic logs to a CSV file.
*   **Ready for Deployment**: Includes a `render.yaml` file for easy deployment to the Render platform.

## Project Structure

```
/
├── app.py                      # Main Flask application for the dashboard
├── real_website/
│   ├── real_website.py         # Flask app for the simulated "real" website
│   └── templates/              # HTML templates for the real website
├── static/
│   └── style.css               # CSS for the dashboard
├── templates/                  # HTML templates for the dashboard
├── generate_training_data.py   # Script to process raw traffic and create a labeled dataset
├── simulate_traffic.py         # Script to generate simulated benign and malicious traffic
├── train_model.py              # Script to train the ML model
├── ddos_model.pkl              # Saved machine learning model
├── ddos_scaler.pkl             # Saved feature scaler for the model
├── traffic_data.json           # Raw simulated traffic data
├── training_data.csv           # Processed and labeled training data
├── requirements.txt            # Python dependencies
└── render.yaml                 # Deployment configuration for Render
```

## Local Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd DDoS_Project
    ```

2.  **Create a virtual environment and install dependencies:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

3.  **Generate Training Data and Train the Model:**
    *First, you need data. The simulation script will send traffic to the `real_website`.*
    *In one terminal, start the `real_website`:*
    ```bash
    python real_website/real_website.py
    ```
    *In a second terminal, run the traffic simulation:*
    ```bash
    python simulate_traffic.py
    ```
    *This will create `traffic_data.json`. Now, generate the training set and train the model:*
    ```bash
    python generate_training_data.py
    python train_model.py
    ```
    *This will create `training_data.csv`, `ddos_model.pkl`, and `ddos_scaler.pkl`.*

4.  **Run the main dashboard application:**
    ```bash
    python app.py
    ```

5.  **Access the applications:**
    *   **Dashboard**: [http://127.0.0.1:5001](http://127.0.0.1:5001) (Login: `admin`/`password`)
    *   **Real Website**: [http://127.0.0.1:5000](http://127.0.0.1:5000)

## Deployment

This project is configured for deployment on [Render](https://render.com/). The `render.yaml` file defines the necessary services and build steps. Simply connect your GitHub repository to Render and it will automatically deploy the two web services.
