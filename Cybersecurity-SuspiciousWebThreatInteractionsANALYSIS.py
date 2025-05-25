import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import sklearn 
import warnings
warnings.simplefilter(action='ignore',category=FutureWarning)
import streamlit as st
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_absolute_error,r2_score, mean_squared_error
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import streamlit as st
from streamlit_option_menu import option_menu
df=pd.read_csv('CloudWatch_Traffic_Web_Attack.csv')

st.set_page_config(page_title="CYBERSECURITY -SuspiciousWebThreatInteractions Dashboard", layout="wide")
dark_theme = """<style>body {background-color: #121212;color: white;font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;}
            .stSidebar {background-color: #1E1E1E;}.css-1d391kg {color: white;}h1, h2, h3 {color: #6c63ff;}footer {visibility: hidden;}
             #MainMenu {visibility: hidden;}</style>"""
st.markdown(dark_theme, unsafe_allow_html=True)

df['creation_time']=pd.to_datetime(df['creation_time'])
df['end_time']=pd.to_datetime(df['end_time'])
df['time']=pd.to_datetime(df['time'])
df['Duration_time']=(df['end_time']-df['creation_time']).dt.total_seconds()
df['hour']=df['time'].dt.hour
df['day']=df['time'].dt.day
df['weekday']=df['time'].dt.weekday

st.markdown("""<style>[data-testid="stAppViewContainer"] {background-color: #000000;}.kpi-card {background-color: #2e2e2e;padding: 20px;border-                  radius: 15px;box-shadow: 2px 2px 15px rgba(0,0,0,0.4);color: white;text-align: center;margin-bottom: 20px;}.kpi-card h3 {font-size: 18px;color: #f9f9f9;margin-bottom: 5px;}.kpi-card p {font-size: 24px;font-weight: bold;}.card {background-color: #1e1e2f;padding: 20px;border-radius: 15px;box-shadow: 2px 2px 15px rgba(0,0,0,0.4);margin-bottom: 20px;color: white;}.card-title {font-size: 22px;margin-bottom: 10px;
        color: white;font-weight: 600;}</style>""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("""<div style='display: flex; align-items: center; gap: 10px; padding-bottom: 10px;'><img src='https://images.seeklogo.com/logo-png/42/1/cyber-security-logo-png_seeklogo-429139.png' width='35'/><h3 style='color:white; margin: 0;font-size: 28px;'>Cybersecurity Dashboard</h3> </div> """, unsafe_allow_html=True )
    selected = option_menu(menu_title="Dashboard Navigation",options=["Overview KPIs", "Cybersecurity Dataset Exploratory Data Analysis", "Modeling & Results"], icons=["bar-chart", "search", "cpu"], menu_icon="cast", default_index=0,styles={ "container": {"padding": "5px","background-color": "#000000"},"icon": {"color": "white","font-size": "20px" },"nav-link": {"color": "white","font-size": "16px","text-align": "left",
"margin": "5px"},"nav-link-selected": { "background-color": "#6c63ff", "color": "white" },"menu-title": { "color": "white", "font-size": "18px"}} )

if selected == "Overview KPIs":
    st.markdown('<h1 style="color:white;">📊 Overview KPIs</h1>', unsafe_allow_html=True)
    st.markdown('<p style="color:white;">High-level metrics from the cybersecurity traffic data.</p>', unsafe_allow_html=True)
    col1,col2,col3=st.columns(3)
    with col1:
        total_traffic = df['bytes_in'].sum() + df['bytes_out'].sum()
        st.markdown(f""" <div class="kpi-card"><h3>📦 Total Traffic Volume</h3><p>{total_traffic:,} Bytes</p></div>""", unsafe_allow_html=True)

    with col2:
        unique_ips = df['src_ip'].nunique()
        st.markdown(f"""<div class="kpi-card"><h3>🌍 Unique Source IPs</h3><p>{unique_ips}</p></div>""", unsafe_allow_html=True)

    with col3:
        suspicious_count = df[df['detection_types'] != 'Normal'].shape[0]
        suspicious_percent = suspicious_count / len(df) * 100
        st.markdown(f"""<div class="kpi-card"><h3>🔒 Suspicious Requests</h3><p>{suspicious_percent:.2f}%</p></div>""", unsafe_allow_html=True) 
    
    avg_duration = df['Duration_time'].mean()
    max_duration = 800
    fig_duration = go.Figure(go.Indicator(mode="gauge+number",value=avg_duration,title={'text': "Average Session Duration (s)",'font': {'size': 16}},gauge={'axis': {'range': [0, max_duration], 'tickcolor': 'white', 'tickfont': {'color': 'white'}},'bar': {'color': "dodgerblue"},
      'bgcolor': "white",'steps': [ {'range': [0, avg_duration], 'color': "dodgerblue"}, {'range': [avg_duration, max_duration], 'color': "#FFFFFF"}],'threshold': {'line': {'color': "white", 'width': 6},'thickness': 1,'value': avg_duration}}))
    fig_duration.update_layout(paper_bgcolor='black', font={'color': 'white'})

    total_requests = len(df)
    success_count = df[df['response.code'] == 200].shape[0]
    success_rate = (success_count / total_requests) * 100
    fig_success = go.Figure(go.Indicator(mode="gauge+number",value=success_rate,title={'text': "Response Code Success Rate (%)", 'font': {'size': 16}},gauge={'axis': {'range': [0, 100], 'tickcolor': 'white', 'tickfont': {'color': 'white'}},'bar': {'color': "mediumseagreen"},
        'bgcolor': "black",'steps': [{'range': [0, success_rate], 'color': "mediumseagreen"},{'range': [success_rate, 100], 'color': "#222222"}],
        'threshold': {'line': {'color': "white", 'width': 6},'thickness': 1,'value': success_rate}}))
    fig_success.update_layout(paper_bgcolor='black', font={'color': 'white'})

    col1, col2 = st.columns(2)
    with col1:
        st.markdown('<div class="card"><div class="card-title">📈 Average Session Duration</div>', unsafe_allow_html=True)
        st.plotly_chart(fig_duration, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="card"><div class="card-title">✅ Success Rate</div>', unsafe_allow_html=True)
        st.plotly_chart(fig_success, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)   

elif selected == "Cybersecurity Dataset Exploratory Data Analysis":
    st.markdown('<h1 style="color:white; ">📈 Cybersecurity Dataset Exploratory Data Analysis</h1>', unsafe_allow_html=True)
    st.markdown('<p style="color:white;">Visual insights into traffic patterns and suspicious activities.</p>', unsafe_allow_html=True)
    col1,col2=st.columns(2)
    with col1:
        df_long = pd.melt(df, value_vars=['bytes_in', 'bytes_out'], var_name='Traffic Type', value_name='Bytes')
        medians = df_long.groupby('Traffic Type')['Bytes'].median()
        fig, ax = plt.subplots(figsize=(8,5))
        fig.patch.set_facecolor('black')
        ax.set_facecolor('black')
        sns.violinplot(x='Traffic Type', y='Bytes', data=df_long, palette=['blue', 'green'], ax=ax)
        for i, traffic_type in enumerate(medians.index):
            median_val = medians[traffic_type]
            ax.text(i, median_val, f'{median_val:.0f}', color='white', ha='center', va='bottom', fontweight='bold')
        ax.set_title('Distribution of Incoming & Outgoing Web Traffic', color='white', fontsize=16)
        ax.tick_params(colors='white')
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.yaxis.label.set_color('white')
        ax.xaxis.label.set_color('white')
        plt.tight_layout()
        st.pyplot(fig,use_container_width=True)
    with col2:
        fig, ax = plt.subplots(figsize=(4.5,3.5))
        fig.patch.set_facecolor('black')
        ax.set_facecolor('black')
        ax.plot(df.index, df['bytes_in'], label='Bytes In', marker='o', color='cyan')
        ax.plot(df.index, df['bytes_out'], label='Bytes Out', marker='o', color='orange')
        ax.set_title('Web Traffic Analysis Over Time', color='white')
        ax.set_xlabel('Time', color='white')
        ax.set_ylabel('Bytes', color='white')
        ax.tick_params(colors='white')
        ax.legend()
        ax.grid(True, color='gray')
        plt.xticks(rotation=45)
        plt.tight_layout()
        st.pyplot(fig,use_container_width=True)
    
    col3,col4=st.columns(2)
    with col3:
        hourly=df.groupby('hour')[['bytes_in', 'bytes_out']].sum().reset_index()
        fig, ax = plt.subplots(figsize=(5,5))
        fig.patch.set_facecolor('black')
        ax.set_facecolor('black')
        hourly[['bytes_in', 'bytes_out']].plot(kind='area', stacked=False, alpha=0.5, cmap='coolwarm', ax=ax)
        plt.legend()
        plt.ylabel('Total Bytes', color='white')
        plt.xlabel('Hours of the Day', color='white')
        plt.title('Traffic by Hours: Bytes In vs Bytes Out', color='white')
        plt.grid(True, linestyle='--', alpha=0.6, color='gray')
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')
        plt.tight_layout()
        st.pyplot(fig,use_container_width=True)
    with col4:
        df.set_index('time')
        hourly = df.resample('H', on='time').size()
        hourly_df = hourly.reset_index()
        hourly_df.columns = ['time', 'Attack Count']
        fig = px.line(hourly, title='Attack Frequency Over Time', labels={'Attack Count': 'Attack Count'},color_discrete_sequence=['red'])
        fig.update_layout(template='plotly_dark',paper_bgcolor='black',plot_bgcolor='black',font=dict(color='white'),
        title_font=dict(color='white'),xaxis=dict(title_font=dict(color='white'), tickfont=dict(color='white')),
        yaxis=dict(title_font=dict(color='white'), tickfont=dict(color='white')))
        st.plotly_chart(fig, use_container_width=True)

    col5,col6=st.columns(2)
    with col5:
        df['date'] = df['time'].dt.date
        daily_attacks = df.groupby('date')['detection_types'].count().reset_index(name='WAF Trigger Count')
        fig_daily = px.line(daily_attacks,x='date',y='WAF Trigger Count',title='Daily WAF Rule Triggers',color_discrete_sequence=['orange'],
                    labels={'date': 'Date', 'WAF Trigger Count': 'WAF Trigger Count'})
        fig_daily.update_layout(template='plotly_dark',title_font_size=18,xaxis_title='Date',yaxis_title='Number of WAF Detections',
        hovermode='x unified',margin=dict(l=40, r=40, t=60,b=40),paper_bgcolor='black',plot_bgcolor='black',font=dict(color='white'),
        title_font=dict(color='white'),xaxis=dict(title_font=dict(color='white'), tickfont=dict(color='white')),
        yaxis=dict(title_font=dict(color='white'), tickfont=dict(color='white')))
        fig_daily.update_traces(line=dict(width=2), marker=dict(size=4))
        st.plotly_chart(fig_daily, use_container_width=True, key="unique_key_2")  
        
    with col6:
        detection_types_by_country = pd.crosstab(df['src_ip_country_code'], df['detection_types']).reset_index()
        df_long = detection_types_by_country.melt(id_vars='src_ip_country_code', var_name='Detection Type', value_name='Frequency')
        fig = px.bar(df_long,  x='src_ip_country_code', y='Frequency', title='Detection Types by Country Code', 
             labels={'src_ip_country_code':'Country Code', 'Frequency':'Frequency of Detection Types'},template='plotly_dark',
             color_discrete_sequence=px.colors.qualitative.D3 )
        fig.update_layout(xaxis_tickangle=45, barmode='stack',paper_bgcolor='black',plot_bgcolor='black',font=dict(color='white'),
        title_font=dict(color='white'),xaxis=dict(title_font=dict(color='white'), tickfont=dict(color='white')),
        yaxis=dict(title_font=dict(color='white'), tickfont=dict(color='white')))
        st.plotly_chart(fig, use_container_width=True ,key="unique_key_3")

    col7,col8=st.columns(2)
    with col7:
        top_ips = df['src_ip'].value_counts().head(10).reset_index()
        top_ips.columns = ['Source IP', 'Count']
        fig = px.bar(top_ips, x='Source IP', y='Count', title='Top 10 Source IPs',color='Count')
        fig.update_layout(template='plotly_dark',paper_bgcolor='black',plot_bgcolor='black',font=dict(color='white'),title_font=dict(color='white'),
        xaxis=dict(title_font=dict(color='white'), tickfont=dict(color='white')),yaxis=dict(title_font=dict(color='white'), tickfont=dict(color='white')))
        st.plotly_chart(fig, use_container_width=True, key="unique_key_4")
    with col8:
        df['weekday_name'] = df['weekday'].map({0: 'Monday', 1: 'Tuesday', 2: 'Wednesday',3: 'Thursday', 4: 'Friday', 5: 'Saturday', 6: 'Sunday'})
        pivot = df.pivot_table(index='weekday_name', columns='hour', aggfunc='size', fill_value=0)
        ordered_days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        pivot = pivot.reindex(ordered_days)
        pivot = pivot.reset_index()
        pivot_long = pivot.melt(id_vars='weekday_name', var_name='Hour', value_name='Alert Count')
        fig = px.density_heatmap(pivot_long,x='Hour',y='weekday_name',z='Alert Count',color_continuous_scale='YlOrRd',
                         labels={'weekday_name': 'Day', 'Hour': 'Hour', 'Alert Count': 'Alerts'},
        title='Hourly Alert Heatmap')
        fig.update_layout(template='plotly_dark', xaxis_nticks=24,paper_bgcolor='black',plot_bgcolor='black',font=dict(color='white'),
        title_font=dict(color='white'),xaxis=dict(title_font=dict(color='white'), tickfont=dict(color='white')),
        yaxis=dict(title_font=dict(color='white'), tickfont=dict(color='white')))
        st.plotly_chart(fig, use_container_width=True ,key="unique_key_5")

elif selected == "Modeling & Results":
    st.markdown('<h1 style="color:white;">🧠 Modeling & Results</h1>', unsafe_allow_html=True)
    st.markdown('<p style="color:white;">Anomaly detection insights and model performance.</p>', unsafe_allow_html=True)
    df = df.dropna(subset=['detection_types'])
    le_target = LabelEncoder()
    df['detection_encoded'] = le_target.fit_transform(df['detection_types'])
    features = ['bytes_in', 'bytes_out', 'dst_port']  

    df['src_ip_country_code_enc'] = LabelEncoder().fit_transform(df['src_ip_country_code'].astype(str))
    df['protocol_enc'] = LabelEncoder().fit_transform(df['protocol'].astype(str))

    features = ['src_ip_country_code_enc', 'protocol_enc']
    X = df[features]
    y = df['detection_encoded']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)

    col1,col2=st.columns(2)
    with col1:
        y_pred = rf.predict(X_test)
        print(classification_report(y_test, y_pred, target_names=le_target.classes_))
        cm = confusion_matrix(y_test, y_pred)
        fig,ax=plt.subplots(figsize=(5,5))
        fig.patch.set_facecolor('black')
        ax.set_facecolor('black')
        ax=sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',xticklabels=le_target.classes_, yticklabels=le_target.classes_)
        ax.set_xlabel('Predicted',color='white')
        ax.set_ylabel('Actual',color='white')
        ax.set_title('Confusion Matrix',color='white')
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')
        st.pyplot(fig,use_container_width=True)

    features = ['bytes_in', 'bytes_out', 'dst_port']
    df['src_ip_country_code_enc'] = LabelEncoder().fit_transform(df['src_ip_country_code'].astype(str))
    df['protocol_enc'] = LabelEncoder().fit_transform(df['protocol'].astype(str))
    features = ['src_ip_country_code_enc', 'protocol_enc']
    X = df[features]
    iso_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)  # contamination ~ expected outlier % (tune it)
    iso_forest.fit(X)
    df['anomaly_score'] = iso_forest.decision_function(X)  
    df['anomaly_label'] = iso_forest.predict(X)

    with col2:
        fig,ax=plt.subplots(figsize=(5,5))
        fig.patch.set_facecolor('black')
        ax.set_facecolor('black')
        ax=sns.countplot(x='anomaly_label', data=df, palette='Set2')
        ax.set_title("Anomaly vs Normal Traffic",color='white')
        ax.set_xticks([0, 1])
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')
        ax.set_xticklabels(['Anomaly (-1)', 'Normal (1)'])
        st.pyplot(fig,use_container_width=True)

    col3,col4=st.columns(2)
    with col3:
        fig,ax=plt.subplots(figsize=(5,5))
        fig.patch.set_facecolor('black')
        ax.set_facecolor('black')
        ax=sns.scatterplot(data=df, x='bytes_in', y='bytes_out', hue='anomaly_label', palette={1:'green', -1:'red'}, alpha=0.7)
        ax.set_title("Anomaly Detection - Traffic Behavior",color='white')
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')
        plt.legend(title='Label', labels=['Anomaly', 'Normal'])
        st.pyplot(fig,use_container_width=True)
        
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(X)
    isolation_forest = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
    isolation_forest.fit(scaled_features)
    df['is_anomaly'] = (isolation_forest.predict(scaled_features) == -1).astype(int)
    print(df['is_anomaly'].value_counts())
    with col4:
        fig,ax=plt.subplots(figsize=(5,5))
        fig.patch.set_facecolor('black')
        ax.set_facecolor('black')
        df_all = df.copy()
        df_anomaly = df[df['is_anomaly'] == 1].copy()
        attack_counts = df_all.resample('H', on='time').size().reset_index(name='Attack Count')
        anomaly_counts = df_anomaly.resample('H', on='time').size().reset_index(name='Anomaly Count')
        ax.plot(attack_counts['time'], attack_counts['Attack Count'], label='All Attacks', color='blue')
        ax.plot(anomaly_counts['time'], anomaly_counts['Anomaly Count'], label='Anomalies', color='red')
        ax.set_title('Attack & Anomaly Frequency Over Time',color='white')
        ax.set_xlabel('Time',color='white')
        ax.set_ylabel('Count',color='white')
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')
        ax.legend()
        ax.tick_params(axis='x', rotation=45)
        st.pyplot(fig, use_container_width=True)
    
st.markdown("<p style='text-align: center; font-size: 16px; color: white;'>Made by Nikita Mendhe | <a href='www.linkedin.com/in/nikita-mendhe-2067b5210' target='_blank'>LinkedIn</a></p>", unsafe_allow_html=True)