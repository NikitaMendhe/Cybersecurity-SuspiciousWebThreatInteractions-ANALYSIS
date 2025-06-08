**Cybersecurity - Suspicious Web Threat Interactions Analysis**
This project focuses on analyzing web traffic logs and detecting suspicious interactions to support cybersecurity threat intelligence. Using advanced EDA, feature engineering, and machine learning techniques, we uncover hidden patterns, identify high-risk IPs, and visualize threats for quick decision-making through a Streamlit dashboard.

## 📁 Dataset

- **File:** `CloudWatch_Traffic_Web_Attack.csv`
- **Source:** AWS CloudWatch logs (simulated or anonymized)
- **Key Columns:**
  - `bytes_in`, `bytes_out`, `protocol`, `dst_port`, `rule_names`, `detection_types`
  - `src_ip`, `dst_ip`, `src_ip_country_code`, `observation_name`
  - Timestamps: `creation_time`, `end_time`, `time`
  - Metadata fields: `source.meta`, `source.name`

## 🎯 Objectives

- Detect patterns in suspicious web traffic.
- Profile attackers using geo-location and IP metadata.
- Identify top threat types and detection rule matches.
- Build an interactive cybersecurity monitoring dashboard.
- Explore anomaly detection and clustering for advanced insight.

- ## 🛠️ Tools & Technologies

- **Language:** Python
- **Libraries:** `pandas`, `numpy`, `matplotlib`, `seaborn`, `plotly`, `scikit-learn`,  `streamlit`
- **Dashboard:** Streamlit
- **Notebook:** Jupyter (`Cybersecurity-SuspiciousWebThreatInteractions.ipynb`)

**🙌 Acknowledgements**
  This project is developed as part of a cybersecurity data science initiative to help visualize and detect network threats using advanced data analytics.
