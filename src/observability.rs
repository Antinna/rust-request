//! Advanced observability and monitoring capabilities
//!
//! This module provides comprehensive observability features including metrics collection,
//! health monitoring, alerting, and performance analytics for HTTP operations.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Comprehensive observability manager
#[derive(Debug)]
pub struct ObservabilityManager {
    metrics_collector: MetricsCollector,
    health_monitor: HealthMonitor,
    alert_manager: AlertManager,
    performance_analyzer: PerformanceAnalyzer,
}

/// Advanced metrics collection system
#[derive(Debug)]
pub struct MetricsCollector {
    counters: Arc<RwLock<HashMap<String, u64>>>,
    gauges: Arc<RwLock<HashMap<String, f64>>>,
    histograms: Arc<RwLock<HashMap<String, Histogram>>>,
    timers: Arc<RwLock<HashMap<String, Timer>>>,
}

/// Health monitoring system
#[derive(Debug)]
pub struct HealthMonitor {
    health_checks: Arc<RwLock<HashMap<String, HealthCheck>>>,
    system_health: Arc<RwLock<SystemHealth>>,
}

/// Alert management system
#[derive(Debug)]
pub struct AlertManager {
    alert_rules: Vec<AlertRule>,
    active_alerts: Arc<Mutex<Vec<Alert>>>,
    notification_channels: Vec<NotificationChannel>,
}

/// Performance analysis system
#[derive(Debug)]
pub struct PerformanceAnalyzer {
    performance_data: Arc<RwLock<Vec<PerformanceDataPoint>>>,
    analysis_config: AnalysisConfig,
}

/// Histogram for tracking value distributions
#[derive(Debug, Clone)]
pub struct Histogram {
    buckets: Vec<(f64, u64)>,
    total_count: u64,
    sum: f64,
}

/// Timer for tracking operation durations
#[derive(Debug, Clone)]
pub struct Timer {
    start_time: Option<Instant>,
    total_duration: Duration,
    count: u64,
}

/// Health check definition
#[derive(Debug, Clone)]
pub struct HealthCheck {
    name: String,
    check_fn: fn() -> HealthStatus,
    interval: Duration,
    timeout: Duration,
    last_check: Option<Instant>,
    last_status: HealthStatus,
}

/// System health status
#[derive(Debug, Clone)]
pub struct SystemHealth {
    overall_status: HealthStatus,
    component_health: HashMap<String, HealthStatus>,
    last_updated: Instant,
}

/// Health status enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Alert rule definition
#[derive(Debug, Clone)]
pub struct AlertRule {
    name: String,
    condition: AlertCondition,
    severity: AlertSeverity,
    threshold: f64,
    duration: Duration,
}

/// Alert condition types
#[derive(Debug, Clone)]
pub enum AlertCondition {
    MetricAbove(String),
    MetricBelow(String),
    HealthStatusEquals(String, HealthStatus),
    ErrorRateAbove(f64),
    ResponseTimeAbove(Duration),
}

/// Alert severity levels
#[derive(Debug, Clone, PartialEq)]
pub enum AlertSeverity {
    Critical,
    Warning,
    Info,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Critical => write!(f, "CRITICAL"),
            AlertSeverity::Warning => write!(f, "WARNING"),
            AlertSeverity::Info => write!(f, "INFO"),
        }
    }
}

/// Active alert
#[derive(Debug, Clone)]
pub struct Alert {
    id: String,
    rule_name: String,
    severity: AlertSeverity,
    message: String,
    triggered_at: Instant,
    resolved_at: Option<Instant>,
}

/// Notification channel
#[derive(Debug, Clone)]
pub enum NotificationChannel {
    Email(String),
    Webhook(String),
    Slack(String),
    Console,
}

/// Performance data point
#[derive(Debug, Clone)]
pub struct PerformanceDataPoint {
    timestamp: Instant,
    operation: String,
    duration: Duration,
    success: bool,
    metadata: HashMap<String, String>,
}

impl PerformanceDataPoint {
    pub fn new(operation: String, duration: Duration, success: bool) -> Self {
        PerformanceDataPoint {
            timestamp: Instant::now(),
            operation,
            duration,
            success,
            metadata: HashMap::new(),
        }
    }
    
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    pub fn get_metadata(&self) -> &HashMap<String, String> {
        &self.metadata
    }
    
    pub fn get_metadata_value(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
    
    pub fn get_timestamp(&self) -> Instant {
        self.timestamp
    }
    
    pub fn get_operation(&self) -> &str {
        &self.operation
    }
    
    pub fn get_duration(&self) -> Duration {
        self.duration
    }
    
    pub fn is_success(&self) -> bool {
        self.success
    }
}

/// Analysis configuration
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    window_size: Duration,
    percentiles: Vec<f64>,
    anomaly_detection: bool,
    trend_analysis: bool,
}

impl AnalysisConfig {
    pub fn new() -> Self {
        AnalysisConfig {
            window_size: Duration::from_secs(300), // 5 minutes
            percentiles: vec![50.0, 90.0, 95.0, 99.0],
            anomaly_detection: true,
            trend_analysis: true,
        }
    }
    
    pub fn with_window_size(mut self, window_size: Duration) -> Self {
        self.window_size = window_size;
        self
    }
    
    pub fn with_percentiles(mut self, percentiles: Vec<f64>) -> Self {
        self.percentiles = percentiles;
        self
    }
    
    pub fn with_anomaly_detection(mut self, enabled: bool) -> Self {
        self.anomaly_detection = enabled;
        self
    }
    
    pub fn with_trend_analysis(mut self, enabled: bool) -> Self {
        self.trend_analysis = enabled;
        self
    }
    
    pub fn get_window_size(&self) -> Duration {
        self.window_size
    }
    
    pub fn get_percentiles(&self) -> &[f64] {
        &self.percentiles
    }
    
    pub fn is_anomaly_detection_enabled(&self) -> bool {
        self.anomaly_detection
    }
    
    pub fn is_trend_analysis_enabled(&self) -> bool {
        self.trend_analysis
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Performance analysis result
#[derive(Debug, Clone)]
pub struct PerformanceAnalysis {
    operation: String,
    window: Duration,
    total_requests: u64,
    success_rate: f64,
    average_duration: Duration,
    percentiles: HashMap<String, Duration>,
    trends: Vec<Trend>,
    anomalies: Vec<Anomaly>,
}

impl PerformanceAnalysis {
    pub fn get_operation(&self) -> &str {
        &self.operation
    }
    
    pub fn get_window(&self) -> Duration {
        self.window
    }
    
    pub fn get_total_requests(&self) -> u64 {
        self.total_requests
    }
    
    pub fn get_success_rate(&self) -> f64 {
        self.success_rate
    }
    
    pub fn get_average_duration(&self) -> Duration {
        self.average_duration
    }
    
    pub fn get_percentiles(&self) -> &HashMap<String, Duration> {
        &self.percentiles
    }
    
    pub fn get_trends(&self) -> &[Trend] {
        &self.trends
    }
    
    pub fn get_anomalies(&self) -> &[Anomaly] {
        &self.anomalies
    }
    
    pub fn has_performance_issues(&self) -> bool {
        !self.anomalies.is_empty() || 
        self.trends.iter().any(|t| t.direction == TrendDirection::Increasing && t.magnitude > 0.2)
    }
}

/// Performance trend
#[derive(Debug, Clone)]
pub struct Trend {
    pub metric: String,
    pub direction: TrendDirection,
    pub magnitude: f64,
    pub confidence: f64,
}

impl Trend {
    pub fn get_metric(&self) -> &str {
        &self.metric
    }
    
    pub fn get_direction(&self) -> &TrendDirection {
        &self.direction
    }
    
    pub fn get_magnitude(&self) -> f64 {
        self.magnitude
    }
    
    pub fn get_confidence(&self) -> f64 {
        self.confidence
    }
    
    pub fn is_significant(&self) -> bool {
        self.magnitude > 0.1 && self.confidence > 0.7
    }
}

/// Trend direction
#[derive(Debug, Clone, PartialEq)]
pub enum TrendDirection {
    Increasing,
    Decreasing,
    Stable,
}

/// Performance anomaly
#[derive(Debug, Clone)]
pub struct Anomaly {
    pub timestamp: Instant,
    pub metric: String,
    pub expected_value: f64,
    pub actual_value: f64,
    pub severity: f64,
}

impl Anomaly {
    pub fn get_timestamp(&self) -> Instant {
        self.timestamp
    }
    
    pub fn get_metric(&self) -> &str {
        &self.metric
    }
    
    pub fn get_expected_value(&self) -> f64 {
        self.expected_value
    }
    
    pub fn get_actual_value(&self) -> f64 {
        self.actual_value
    }
    
    pub fn get_severity(&self) -> f64 {
        self.severity
    }
    
    pub fn get_deviation_percentage(&self) -> f64 {
        if self.expected_value != 0.0 {
            ((self.actual_value - self.expected_value) / self.expected_value * 100.0).abs()
        } else {
            0.0
        }
    }
    
    pub fn is_critical(&self) -> bool {
        self.severity > 2.0
    }
}

impl ObservabilityManager {
    pub fn new() -> Self {
        ObservabilityManager {
            metrics_collector: MetricsCollector::new(),
            health_monitor: HealthMonitor::new(),
            alert_manager: AlertManager::new(),
            performance_analyzer: PerformanceAnalyzer::new(),
        }
    }

    pub fn record_request(&self, operation: &str, duration: Duration, success: bool) {
        // Record metrics
        self.metrics_collector
            .increment_counter(&format!("{operation}_requests_total"));
        if success {
            self.metrics_collector
                .increment_counter(&format!("{operation}_requests_success"));
        } else {
            self.metrics_collector
                .increment_counter(&format!("{operation}_requests_error"));
        }

        self.metrics_collector.record_histogram(
            &format!("{operation}_duration"),
            duration.as_millis() as f64,
        );

        // Record performance data
        self.performance_analyzer
            .record_data_point(PerformanceDataPoint {
                timestamp: Instant::now(),
                operation: operation.to_string(),
                duration,
                success,
                metadata: HashMap::new(),
            });

        // Check alerts
        self.alert_manager.evaluate_rules(&self.metrics_collector);
    }

    pub fn get_metrics_summary(&self) -> MetricsSummary {
        self.metrics_collector.get_summary()
    }

    pub fn get_health_status(&self) -> SystemHealth {
        self.health_monitor.get_system_health()
    }

    pub fn get_active_alerts(&self) -> Vec<Alert> {
        self.alert_manager.get_active_alerts()
    }

    pub fn analyze_performance(&self, operation: &str, window: Duration) -> PerformanceAnalysis {
        self.performance_analyzer
            .analyze_operation(operation, window)
    }
}

impl Default for ObservabilityManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        MetricsCollector {
            counters: Arc::new(RwLock::new(HashMap::new())),
            gauges: Arc::new(RwLock::new(HashMap::new())),
            histograms: Arc::new(RwLock::new(HashMap::new())),
            timers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn increment_counter(&self, name: &str) {
        let mut counters = self.counters.write().unwrap();
        *counters.entry(name.to_string()).or_insert(0) += 1;
    }

    pub fn set_gauge(&self, name: &str, value: f64) {
        let mut gauges = self.gauges.write().unwrap();
        gauges.insert(name.to_string(), value);
    }

    pub fn record_histogram(&self, name: &str, value: f64) {
        let mut histograms = self.histograms.write().unwrap();
        let histogram = histograms
            .entry(name.to_string())
            .or_default();
        histogram.record(value);
    }

    pub fn start_timer(&self, name: &str) {
        let mut timers = self.timers.write().unwrap();
        let timer = timers
            .entry(name.to_string())
            .or_default();
        timer.start();
    }

    pub fn stop_timer(&self, name: &str) {
        let mut timers = self.timers.write().unwrap();
        if let Some(timer) = timers.get_mut(name) {
            timer.stop();
        }
    }

    pub fn get_counter(&self, name: &str) -> u64 {
        self.counters
            .read()
            .unwrap()
            .get(name)
            .copied()
            .unwrap_or(0)
    }

    pub fn get_gauge(&self, name: &str) -> f64 {
        self.gauges
            .read()
            .unwrap()
            .get(name)
            .copied()
            .unwrap_or(0.0)
    }

    pub fn get_summary(&self) -> MetricsSummary {
        let counters = self.counters.read().unwrap().clone();
        let gauges = self.gauges.read().unwrap().clone();
        let histograms = self.histograms.read().unwrap();

        let histogram_summaries: HashMap<String, HistogramSummary> = histograms
            .iter()
            .map(|(name, hist)| (name.clone(), hist.summary()))
            .collect();

        MetricsSummary {
            counters,
            gauges,
            histograms: histogram_summaries,
            timestamp: Instant::now(),
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Histogram {
    pub fn new() -> Self {
        // Create buckets for common latency ranges
        let buckets = vec![
            (1.0, 0),
            (5.0, 0),
            (10.0, 0),
            (25.0, 0),
            (50.0, 0),
            (100.0, 0),
            (250.0, 0),
            (500.0, 0),
            (1000.0, 0),
            (2500.0, 0),
            (5000.0, 0),
            (10000.0, 0),
            (f64::INFINITY, 0),
        ];

        Histogram {
            buckets,
            total_count: 0,
            sum: 0.0,
        }
    }

    pub fn record(&mut self, value: f64) {
        self.total_count += 1;
        self.sum += value;

        for (threshold, count) in &mut self.buckets {
            if value <= *threshold {
                *count += 1;
            }
        }
    }

    pub fn summary(&self) -> HistogramSummary {
        HistogramSummary {
            count: self.total_count,
            sum: self.sum,
            average: if self.total_count > 0 {
                self.sum / self.total_count as f64
            } else {
                0.0
            },
            buckets: self.buckets.clone(),
        }
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

impl Timer {
    pub fn new() -> Self {
        Timer {
            start_time: None,
            total_duration: Duration::from_millis(0),
            count: 0,
        }
    }

    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }

    pub fn stop(&mut self) {
        if let Some(start) = self.start_time.take() {
            self.total_duration += start.elapsed();
            self.count += 1;
        }
    }

    pub fn average_duration(&self) -> Duration {
        if self.count > 0 {
            self.total_duration / self.count as u32
        } else {
            Duration::from_millis(0)
        }
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthMonitor {
    pub fn new() -> Self {
        HealthMonitor {
            health_checks: Arc::new(RwLock::new(HashMap::new())),
            system_health: Arc::new(RwLock::new(SystemHealth {
                overall_status: HealthStatus::Unknown,
                component_health: HashMap::new(),
                last_updated: Instant::now(),
            })),
        }
    }

    pub fn register_health_check(&self, check: HealthCheck) {
        let mut checks = self.health_checks.write().unwrap();
        checks.insert(check.name.clone(), check);
    }

    pub fn run_health_checks(&self) {
        let mut checks = self.health_checks.write().unwrap();
        let mut system_health = self.system_health.write().unwrap();

        for (name, check) in checks.iter_mut() {
            if check.should_run() {
                let status = (check.check_fn)();
                check.last_status = status.clone();
                check.last_check = Some(Instant::now());
                system_health.component_health.insert(name.clone(), status);
            }
        }

        // Calculate overall health
        system_health.overall_status =
            self.calculate_overall_health(&system_health.component_health);
        system_health.last_updated = Instant::now();
    }

    pub fn get_system_health(&self) -> SystemHealth {
        self.system_health.read().unwrap().clone()
    }

    fn calculate_overall_health(
        &self,
        component_health: &HashMap<String, HealthStatus>,
    ) -> HealthStatus {
        if component_health.is_empty() {
            return HealthStatus::Unknown;
        }

        let mut healthy_count = 0;
        let mut degraded_count = 0;
        let mut unhealthy_count = 0;

        for status in component_health.values() {
            match status {
                HealthStatus::Healthy => healthy_count += 1,
                HealthStatus::Degraded => degraded_count += 1,
                HealthStatus::Unhealthy => unhealthy_count += 1,
                HealthStatus::Unknown => {}
            }
        }

        if unhealthy_count > 0 {
            HealthStatus::Unhealthy
        } else if degraded_count > 0 {
            HealthStatus::Degraded
        } else if healthy_count > 0 {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unknown
        }
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthCheck {
    pub fn new(name: String, check_fn: fn() -> HealthStatus) -> Self {
        HealthCheck {
            name,
            check_fn,
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            last_check: None,
            last_status: HealthStatus::Unknown,
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn should_run(&self) -> bool {
        match self.last_check {
            Some(last) => last.elapsed() >= self.interval,
            None => true,
        }
    }
}

impl AlertManager {
    pub fn new() -> Self {
        AlertManager {
            alert_rules: Vec::new(),
            active_alerts: Arc::new(Mutex::new(Vec::new())),
            notification_channels: Vec::new(),
        }
    }

    pub fn add_rule(&mut self, rule: AlertRule) {
        self.alert_rules.push(rule);
    }
    
    pub fn get_rule_by_name(&self, name: &str) -> Option<&AlertRule> {
        self.alert_rules.iter().find(|rule| rule.name == name)
    }
    
    pub fn remove_rule(&mut self, name: &str) -> bool {
        if let Some(pos) = self.alert_rules.iter().position(|rule| rule.name == name) {
            self.alert_rules.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn add_notification_channel(&mut self, channel: NotificationChannel) {
        self.notification_channels.push(channel);
    }

    pub fn evaluate_rules(&self, metrics: &MetricsCollector) {
        for rule in &self.alert_rules {
            if self.should_trigger_alert(rule, metrics) {
                self.trigger_alert(rule);
            }
        }
    }

    pub fn get_active_alerts(&self) -> Vec<Alert> {
        self.active_alerts.lock().unwrap().clone()
    }

    fn should_trigger_alert(&self, rule: &AlertRule, metrics: &MetricsCollector) -> bool {
        // Check if alert has been active for the required duration
        let active_alerts = self.active_alerts.lock().unwrap();
        let existing_alert = active_alerts.iter().find(|alert| alert.rule_name == rule.name);
        
        let condition_met = match &rule.condition {
            AlertCondition::MetricAbove(metric_name) => {
                let value = metrics.get_gauge(metric_name);
                value > rule.threshold
            }
            AlertCondition::MetricBelow(metric_name) => {
                let value = metrics.get_gauge(metric_name);
                value < rule.threshold
            }
            AlertCondition::ErrorRateAbove(threshold) => {
                let errors = metrics.get_counter("requests_error") as f64;
                let total = metrics.get_counter("requests_total") as f64;
                if total > 0.0 {
                    (errors / total) > *threshold
                } else {
                    false
                }
            }
            _ => false, // Other conditions not implemented yet
        };
        
        // Only trigger if condition is met and no existing alert, or existing alert has been active for duration
        condition_met && (existing_alert.is_none() || 
            existing_alert.map(|alert| alert.triggered_at.elapsed() >= rule.duration).unwrap_or(false))
    }

    fn trigger_alert(&self, rule: &AlertRule) {
        let alert = Alert {
            id: format!("alert_{}_{}", rule.name, Instant::now().elapsed().as_nanos()),
            rule_name: rule.name.clone(),
            severity: rule.severity.clone(),
            message: format!("Alert triggered: {} - Threshold: {}", rule.name, rule.threshold),
            triggered_at: Instant::now(),
            resolved_at: None,
        };

        self.active_alerts.lock().unwrap().push(alert.clone());
        self.send_notification(&alert);
    }
    
    pub fn resolve_alert(&self, alert_id: &str) -> bool {
        let mut alerts = self.active_alerts.lock().unwrap();
        if let Some(alert) = alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.resolved_at = Some(Instant::now());
            true
        } else {
            false
        }
    }
    
    pub fn get_alert_by_id(&self, alert_id: &str) -> Option<Alert> {
        self.active_alerts.lock().unwrap()
            .iter()
            .find(|alert| alert.id == alert_id)
            .cloned()
    }

    fn send_notification(&self, alert: &Alert) {
        for channel in &self.notification_channels {
            match channel {
                NotificationChannel::Console => {
                    println!("ALERT: {} - {}", alert.severity, alert.message);
                }
                NotificationChannel::Email(address) => {
                    println!("Would send email to {}: {}", address, alert.message);
                }
                NotificationChannel::Webhook(url) => {
                    println!("Would send webhook to {}: {}", url, alert.message);
                }
                NotificationChannel::Slack(channel) => {
                    println!("Would send Slack message to {}: {}", channel, alert.message);
                }
            }
        }
    }
}

impl Default for AlertManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PerformanceAnalyzer {
    pub fn new() -> Self {
        PerformanceAnalyzer {
            performance_data: Arc::new(RwLock::new(Vec::new())),
            analysis_config: AnalysisConfig {
                window_size: Duration::from_secs(300), // 5 minutes
                percentiles: vec![50.0, 90.0, 95.0, 99.0],
                anomaly_detection: true,
                trend_analysis: true,
            },
        }
    }

    pub fn record_data_point(&self, data_point: PerformanceDataPoint) {
        let mut data = self.performance_data.write().unwrap();
        data.push(data_point);

        // Keep only recent data
        let cutoff = Instant::now() - self.analysis_config.window_size;
        data.retain(|point| point.timestamp > cutoff);
    }

    pub fn analyze_operation(&self, operation: &str, window: Duration) -> PerformanceAnalysis {
        let data = self.performance_data.read().unwrap();
        let cutoff = Instant::now() - window;

        let relevant_data: Vec<_> = data
            .iter()
            .filter(|point| point.operation == operation && point.timestamp > cutoff)
            .collect();

        if relevant_data.is_empty() {
            return PerformanceAnalysis {
                operation: operation.to_string(),
                window,
                total_requests: 0,
                success_rate: 0.0,
                average_duration: Duration::from_millis(0),
                percentiles: HashMap::new(),
                trends: Vec::new(),
                anomalies: Vec::new(),
            };
        }

        let total_requests = relevant_data.len() as u64;
        let successful_requests = relevant_data.iter().filter(|p| p.success).count() as u64;
        let success_rate = successful_requests as f64 / total_requests as f64;

        let total_duration: Duration = relevant_data.iter().map(|p| p.duration).sum();
        let average_duration = total_duration / total_requests as u32;

        // Calculate percentiles
        let mut durations: Vec<_> = relevant_data.iter().map(|p| p.duration).collect();
        durations.sort();

        let mut percentiles = HashMap::new();
        for &p in &self.analysis_config.percentiles {
            let index = ((p / 100.0) * (durations.len() - 1) as f64) as usize;
            percentiles.insert(format!("p{}", p as u32), durations[index]);
        }

        PerformanceAnalysis {
            operation: operation.to_string(),
            window,
            total_requests,
            success_rate,
            average_duration,
            percentiles,
            trends: Vec::new(),    // Trend analysis would be implemented here
            anomalies: Vec::new(), // Anomaly detection would be implemented here
        }
    }
}

impl Default for PerformanceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics summary structure
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    pub counters: HashMap<String, u64>,
    pub gauges: HashMap<String, f64>,
    pub histograms: HashMap<String, HistogramSummary>,
    pub timestamp: Instant,
}

/// Histogram summary structure
#[derive(Debug, Clone)]
pub struct HistogramSummary {
    pub count: u64,
    pub sum: f64,
    pub average: f64,
    pub buckets: Vec<(f64, u64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observability_manager() {
        let manager = ObservabilityManager::new();

        // Record some requests
        manager.record_request("api_call", Duration::from_millis(100), true);
        manager.record_request("api_call", Duration::from_millis(200), false);

        let summary = manager.get_metrics_summary();
        assert_eq!(summary.counters.get("api_call_requests_total"), Some(&2));
        assert_eq!(summary.counters.get("api_call_requests_success"), Some(&1));
        assert_eq!(summary.counters.get("api_call_requests_error"), Some(&1));
    }

    #[test]
    fn test_metrics_collector() {
        let collector = MetricsCollector::new();

        collector.increment_counter("test_counter");
        collector.increment_counter("test_counter");
        collector.set_gauge("test_gauge", 42.0);
        collector.record_histogram("test_histogram", 100.0);

        assert_eq!(collector.get_counter("test_counter"), 2);
        assert_eq!(collector.get_gauge("test_gauge"), 42.0);

        let summary = collector.get_summary();
        assert_eq!(summary.counters.get("test_counter"), Some(&2));
        assert_eq!(summary.gauges.get("test_gauge"), Some(&42.0));
    }

    #[test]
    fn test_health_monitor() {
        let monitor = HealthMonitor::new();

        let health_check = HealthCheck::new("test_check".to_string(), || HealthStatus::Healthy);
        monitor.register_health_check(health_check);

        monitor.run_health_checks();

        let health = monitor.get_system_health();
        assert_eq!(health.overall_status, HealthStatus::Healthy);
    }

    #[test]
    fn test_alert_manager() {
        let mut alert_manager = AlertManager::new();

        let rule = AlertRule {
            name: "high_error_rate".to_string(),
            condition: AlertCondition::ErrorRateAbove(0.1),
            severity: AlertSeverity::Warning,
            threshold: 0.1,
            duration: Duration::from_secs(60),
        };

        alert_manager.add_rule(rule);
        alert_manager.add_notification_channel(NotificationChannel::Console);

        let metrics = MetricsCollector::new();
        alert_manager.evaluate_rules(&metrics);

        // Should not trigger alert with no data
        assert_eq!(alert_manager.get_active_alerts().len(), 0);
    }

    #[test]
    fn test_performance_analyzer() {
        let analyzer = PerformanceAnalyzer::new();

        // Record some performance data
        analyzer.record_data_point(PerformanceDataPoint {
            timestamp: Instant::now(),
            operation: "test_op".to_string(),
            duration: Duration::from_millis(100),
            success: true,
            metadata: HashMap::new(),
        });

        let analysis = analyzer.analyze_operation("test_op", Duration::from_secs(60));
        assert_eq!(analysis.total_requests, 1);
        assert_eq!(analysis.success_rate, 1.0);
    }
}
