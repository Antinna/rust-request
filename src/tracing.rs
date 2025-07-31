//! Advanced distributed tracing and observability
//! 
//! This module provides comprehensive distributed tracing capabilities for HTTP requests,
//! allowing you to track requests across multiple services and systems.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use std::sync::{Arc, Mutex};
use std::fmt;

/// Unique identifier for a trace
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceId(pub String);

/// Unique identifier for a span within a trace
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpanId(pub String);

/// Trace context for distributed tracing
#[derive(Debug, Clone)]
pub struct TraceContext {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub parent_span_id: Option<SpanId>,
    pub baggage: HashMap<String, String>,
    pub sampling_decision: SamplingDecision,
}

/// Sampling decision for traces
#[derive(Debug, Clone, PartialEq)]
pub enum SamplingDecision {
    Sample,
    NotSample,
    Defer,
}

/// Span represents a single operation within a trace
#[derive(Debug, Clone)]
pub struct Span {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub parent_span_id: Option<SpanId>,
    pub operation_name: String,
    pub start_time: SystemTime,
    pub end_time: Option<SystemTime>,
    pub duration: Option<std::time::Duration>,
    pub tags: HashMap<String, String>,
    pub logs: Vec<LogEntry>,
    pub status: SpanStatus,
}

/// Status of a span
#[derive(Debug, Clone, PartialEq)]
pub enum SpanStatus {
    Ok,
    Error,
    Timeout,
    Cancelled,
}

/// Log entry within a span
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: SystemTime,
    pub level: LogLevel,
    pub message: String,
    pub fields: HashMap<String, String>,
}

/// Log levels for span logs
#[derive(Debug, Clone, PartialEq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// Tracer for creating and managing spans
pub struct Tracer {
    service_name: String,
    active_spans: Arc<Mutex<HashMap<SpanId, Span>>>,
    finished_spans: Arc<Mutex<Vec<Span>>>,
    sampler: Box<dyn Sampler + Send + Sync>,
    max_spans: usize,
}

/// Sampling strategy trait
pub trait Sampler {
    fn should_sample(&self, trace_id: &TraceId, operation_name: &str) -> SamplingDecision;
}

/// Constant sampler - always samples or never samples
pub struct ConstantSampler {
    decision: SamplingDecision,
}

/// Probabilistic sampler - samples based on probability
pub struct ProbabilisticSampler {
    rate: f64,
}

/// Rate limiting sampler - limits samples per second
pub struct RateLimitingSampler {
    max_traces_per_second: f64,
    last_sample_time: Arc<Mutex<Instant>>,
    traces_this_second: Arc<Mutex<u32>>,
}

/// Span builder for creating spans with fluent API
pub struct SpanBuilder {
    tracer: Arc<Tracer>,
    operation_name: String,
    parent_context: Option<TraceContext>,
    tags: HashMap<String, String>,
    start_time: Option<SystemTime>,
}

/// Active span that automatically finishes when dropped
pub struct ActiveSpan {
    span: Span,
    tracer: Arc<Tracer>,
}

/// Summary of a complete trace
#[derive(Debug, Clone)]
pub struct TraceSummary {
    pub trace_id: TraceId,
    pub total_duration: std::time::Duration,
    pub span_count: usize,
    pub error_count: usize,
    pub spans: Vec<Span>,
}

/// Statistics for a service
#[derive(Debug, Clone)]
pub struct ServiceStats {
    pub service_name: String,
    pub total_spans: usize,
    pub active_spans: usize,
    pub error_spans: usize,
    pub avg_duration: std::time::Duration,
}

impl TraceId {
    pub fn new() -> Self {
        TraceId(format!("{:016x}", rand_u64()))
    }
    
    pub fn from_string(s: String) -> Self {
        TraceId(s)
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::new()
    }
}

impl SpanId {
    pub fn new() -> Self {
        SpanId(format!("{:08x}", rand_u32()))
    }
    
    pub fn from_string(s: String) -> Self {
        SpanId(s)
    }
}

impl Default for SpanId {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceContext {
    pub fn new() -> Self {
        TraceContext {
            trace_id: TraceId::new(),
            span_id: SpanId::new(),
            parent_span_id: None,
            baggage: HashMap::new(),
            sampling_decision: SamplingDecision::Sample,
        }
    }
    
    pub fn child_context(&self) -> Self {
        TraceContext {
            trace_id: self.trace_id.clone(),
            span_id: SpanId::new(),
            parent_span_id: Some(self.span_id.clone()),
            baggage: self.baggage.clone(),
            sampling_decision: self.sampling_decision.clone(),
        }
    }
    
    pub fn add_baggage(&mut self, key: String, value: String) {
        self.baggage.insert(key, value);
    }
    
    pub fn get_baggage(&self, key: &str) -> Option<&String> {
        self.baggage.get(key)
    }
    
    /// Convert to HTTP headers for propagation
    pub fn to_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("x-trace-id".to_string(), self.trace_id.0.clone());
        headers.insert("x-span-id".to_string(), self.span_id.0.clone());
        
        if let Some(parent_id) = &self.parent_span_id {
            headers.insert("x-parent-span-id".to_string(), parent_id.0.clone());
        }
        
        // Add baggage as headers
        for (key, value) in &self.baggage {
            headers.insert(format!("x-baggage-{key}"), value.clone());
        }
        
        headers
    }
    
    /// Create from HTTP headers
    pub fn from_headers(headers: &HashMap<String, String>) -> Option<Self> {
        let trace_id = headers.get("x-trace-id")?.clone();
        let span_id = headers.get("x-span-id")?.clone();
        
        let parent_span_id = headers.get("x-parent-span-id")
            .map(|id| SpanId::from_string(id.clone()));
        
        let mut baggage = HashMap::new();
        for (key, value) in headers {
            if key.starts_with("x-baggage-") {
                let baggage_key = key.strip_prefix("x-baggage-").unwrap();
                baggage.insert(baggage_key.to_string(), value.clone());
            }
        }
        
        Some(TraceContext {
            trace_id: TraceId::from_string(trace_id),
            span_id: SpanId::from_string(span_id),
            parent_span_id,
            baggage,
            sampling_decision: SamplingDecision::Sample,
        })
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Span {
    pub fn new(trace_id: TraceId, span_id: SpanId, operation_name: String) -> Self {
        Span {
            trace_id,
            span_id,
            parent_span_id: None,
            operation_name,
            start_time: SystemTime::now(),
            end_time: None,
            duration: None,
            tags: HashMap::new(),
            logs: Vec::new(),
            status: SpanStatus::Ok,
        }
    }
    
    pub fn set_tag(&mut self, key: String, value: String) {
        self.tags.insert(key, value);
    }
    
    pub fn log(&mut self, level: LogLevel, message: String) {
        self.logs.push(LogEntry {
            timestamp: SystemTime::now(),
            level,
            message,
            fields: HashMap::new(),
        });
    }
    
    pub fn log_with_fields(&mut self, level: LogLevel, message: String, fields: HashMap<String, String>) {
        self.logs.push(LogEntry {
            timestamp: SystemTime::now(),
            level,
            message,
            fields,
        });
    }
    
    pub fn finish(&mut self) {
        let end_time = SystemTime::now();
        self.end_time = Some(end_time);
        self.duration = self.start_time.elapsed().ok();
    }
    
    pub fn set_status(&mut self, status: SpanStatus) {
        self.status = status;
    }
    
    pub fn is_finished(&self) -> bool {
        self.end_time.is_some()
    }
    
    pub fn get_tag(&self, key: &str) -> Option<&String> {
        self.tags.get(key)
    }
    
    pub fn has_error(&self) -> bool {
        self.status == SpanStatus::Error
    }
    
    pub fn elapsed(&self) -> Option<std::time::Duration> {
        if let Some(end_time) = self.end_time {
            end_time.duration_since(self.start_time).ok()
        } else {
            self.start_time.elapsed().ok()
        }
    }
}

impl Tracer {
    pub fn new(service_name: String) -> Self {
        Tracer {
            service_name,
            active_spans: Arc::new(Mutex::new(HashMap::new())),
            finished_spans: Arc::new(Mutex::new(Vec::new())),
            sampler: Box::new(ConstantSampler::new(SamplingDecision::Sample)),
            max_spans: 10000,
        }
    }
    
    pub fn with_max_spans(mut self, max_spans: usize) -> Self {
        self.max_spans = max_spans;
        self
    }
    
    pub fn with_sampler(mut self, sampler: Box<dyn Sampler + Send + Sync>) -> Self {
        self.sampler = sampler;
        self
    }
    
    pub fn start_span(&self, operation_name: &str) -> SpanBuilder {
        SpanBuilder::new(Arc::new(self.clone()), operation_name.to_string())
    }
    
    pub fn start_span_with_context(&self, operation_name: &str, context: TraceContext) -> ActiveSpan {
        let sampling_decision = self.sampler.should_sample(&context.trace_id, operation_name);
        
        if sampling_decision == SamplingDecision::NotSample {
            // Return a no-op span
            return ActiveSpan::new_noop(Arc::new(self.clone()));
        }
        
        let mut span = Span::new(
            context.trace_id.clone(),
            context.span_id.clone(),
            operation_name.to_string(),
        );
        
        span.parent_span_id = context.parent_span_id.clone();
        span.set_tag("service.name".to_string(), self.service_name.clone());
        
        // Add baggage as tags
        for (key, value) in &context.baggage {
            span.set_tag(format!("baggage.{key}"), value.clone());
        }
        
        let span_id = span.span_id.clone();
        self.active_spans.lock().unwrap().insert(span_id.clone(), span.clone());
        
        ActiveSpan {
            span,
            tracer: Arc::new(self.clone()),
        }
    }
    
    pub fn get_active_spans(&self) -> Vec<Span> {
        self.active_spans.lock().unwrap().values().cloned().collect()
    }
    
    pub fn get_finished_spans(&self) -> Vec<Span> {
        self.finished_spans.lock().unwrap().clone()
    }
    
    pub fn finish_span(&self, mut span: Span) {
        span.finish();
        self.active_spans.lock().unwrap().remove(&span.span_id);
        
        let mut finished = self.finished_spans.lock().unwrap();
        if finished.len() >= self.max_spans {
            finished.remove(0); // Remove oldest span
        }
        finished.push(span);
    }
    
    pub fn export_spans(&self) -> Vec<Span> {
        let spans = self.get_finished_spans();
        self.finished_spans.lock().unwrap().clear();
        spans
    }
    
    pub fn get_trace_summary(&self, trace_id: &TraceId) -> Option<TraceSummary> {
        let finished = self.finished_spans.lock().unwrap();
        let trace_spans: Vec<_> = finished.iter()
            .filter(|span| span.trace_id == *trace_id)
            .cloned()
            .collect();
            
        if trace_spans.is_empty() {
            return None;
        }
        
        let total_duration = trace_spans.iter()
            .filter_map(|span| span.duration)
            .max()
            .unwrap_or_default();
            
        let span_count = trace_spans.len();
        let error_count = trace_spans.iter()
            .filter(|span| span.status == SpanStatus::Error)
            .count();
            
        Some(TraceSummary {
            trace_id: trace_id.clone(),
            total_duration,
            span_count,
            error_count,
            spans: trace_spans,
        })
    }
    
    pub fn get_service_stats(&self) -> ServiceStats {
        let finished = self.finished_spans.lock().unwrap();
        let active = self.active_spans.lock().unwrap();
        
        let total_spans = finished.len();
        let active_spans = active.len();
        let error_spans = finished.iter()
            .filter(|span| span.status == SpanStatus::Error)
            .count();
            
        let avg_duration = if !finished.is_empty() {
            let total_duration: std::time::Duration = finished.iter()
                .filter_map(|span| span.duration)
                .sum();
            total_duration / finished.len() as u32
        } else {
            std::time::Duration::default()
        };
        
        ServiceStats {
            service_name: self.service_name.clone(),
            total_spans,
            active_spans,
            error_spans,
            avg_duration,
        }
    }
}

impl Clone for Tracer {
    fn clone(&self) -> Self {
        Tracer {
            service_name: self.service_name.clone(),
            active_spans: Arc::clone(&self.active_spans),
            finished_spans: Arc::clone(&self.finished_spans),
            sampler: Box::new(ConstantSampler::new(SamplingDecision::Sample)),
            max_spans: self.max_spans,
        }
    }
}

impl ConstantSampler {
    pub fn new(decision: SamplingDecision) -> Self {
        ConstantSampler { decision }
    }
}

impl Sampler for ConstantSampler {
    fn should_sample(&self, _trace_id: &TraceId, _operation_name: &str) -> SamplingDecision {
        self.decision.clone()
    }
}

impl ProbabilisticSampler {
    pub fn new(rate: f64) -> Self {
        ProbabilisticSampler { rate: rate.clamp(0.0, 1.0) }
    }
}

impl Sampler for ProbabilisticSampler {
    fn should_sample(&self, trace_id: &TraceId, _operation_name: &str) -> SamplingDecision {
        // Use trace ID to determine sampling (consistent sampling)
        let hash = simple_hash(&trace_id.0);
        let probability = (hash % 10000) as f64 / 10000.0;
        
        if probability < self.rate {
            SamplingDecision::Sample
        } else {
            SamplingDecision::NotSample
        }
    }
}

impl RateLimitingSampler {
    pub fn new(max_traces_per_second: f64) -> Self {
        RateLimitingSampler {
            max_traces_per_second,
            last_sample_time: Arc::new(Mutex::new(Instant::now())),
            traces_this_second: Arc::new(Mutex::new(0)),
        }
    }
}

impl Sampler for RateLimitingSampler {
    fn should_sample(&self, _trace_id: &TraceId, _operation_name: &str) -> SamplingDecision {
        let now = Instant::now();
        let mut last_time = self.last_sample_time.lock().unwrap();
        let mut count = self.traces_this_second.lock().unwrap();
        
        if now.duration_since(*last_time).as_secs() >= 1 {
            *last_time = now;
            *count = 0;
        }
        
        if (*count as f64) < self.max_traces_per_second {
            *count += 1;
            SamplingDecision::Sample
        } else {
            SamplingDecision::NotSample
        }
    }
}

impl SpanBuilder {
    fn new(tracer: Arc<Tracer>, operation_name: String) -> Self {
        SpanBuilder {
            tracer,
            operation_name,
            parent_context: None,
            tags: HashMap::new(),
            start_time: None,
        }
    }
    
    pub fn child_of(mut self, context: TraceContext) -> Self {
        self.parent_context = Some(context);
        self
    }
    
    pub fn with_tag(mut self, key: &str, value: &str) -> Self {
        self.tags.insert(key.to_string(), value.to_string());
        self
    }
    
    pub fn with_start_time(mut self, start_time: SystemTime) -> Self {
        self.start_time = Some(start_time);
        self
    }
    
    pub fn start(self) -> ActiveSpan {
        let context = self.parent_context.unwrap_or_default();
        let child_context = context.child_context();
        
        let mut active_span = self.tracer.start_span_with_context(&self.operation_name, child_context);
        
        // Apply tags
        for (key, value) in self.tags {
            active_span.span.set_tag(key, value);
        }
        
        // Apply custom start time
        if let Some(start_time) = self.start_time {
            active_span.span.start_time = start_time;
        }
        
        active_span
    }
}

impl ActiveSpan {
    fn new_noop(tracer: Arc<Tracer>) -> Self {
        let span = Span::new(
            TraceId::new(),
            SpanId::new(),
            "noop".to_string(),
        );
        
        ActiveSpan { span, tracer }
    }
    
    pub fn set_tag(&mut self, key: &str, value: &str) {
        self.span.set_tag(key.to_string(), value.to_string());
    }
    
    pub fn log(&mut self, level: LogLevel, message: &str) {
        self.span.log(level, message.to_string());
    }
    
    pub fn log_with_fields(&mut self, level: LogLevel, message: &str, fields: HashMap<String, String>) {
        self.span.log_with_fields(level, message.to_string(), fields);
    }
    
    pub fn set_status(&mut self, status: SpanStatus) {
        self.span.set_status(status);
    }
    
    pub fn context(&self) -> TraceContext {
        TraceContext {
            trace_id: self.span.trace_id.clone(),
            span_id: self.span.span_id.clone(),
            parent_span_id: self.span.parent_span_id.clone(),
            baggage: HashMap::new(),
            sampling_decision: SamplingDecision::Sample,
        }
    }
    
    pub fn get_span(&self) -> &Span {
        &self.span
    }
    
    pub fn finish(self) {
        // Span will be finished in Drop
    }
}

impl Drop for ActiveSpan {
    fn drop(&mut self) {
        if !self.span.is_finished() {
            self.tracer.finish_span(self.span.clone());
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Trace => write!(f, "TRACE"),
        }
    }
}

// Utility functions
fn rand_u64() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    now.as_nanos() as u64
}

fn rand_u32() -> u32 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    now.as_nanos() as u32
}

fn simple_hash(s: &str) -> u32 {
    let mut hash = 0u32;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_trace_context_creation() {
        let context = TraceContext::new();
        assert!(!context.trace_id.0.is_empty());
        assert!(!context.span_id.0.is_empty());
        assert!(context.parent_span_id.is_none());
    }
    
    #[test]
    fn test_child_context() {
        let parent = TraceContext::new();
        let child = parent.child_context();
        
        assert_eq!(parent.trace_id.0, child.trace_id.0);
        assert_ne!(parent.span_id.0, child.span_id.0);
        assert_eq!(child.parent_span_id, Some(parent.span_id));
    }
    
    #[test]
    fn test_baggage() {
        let mut context = TraceContext::new();
        context.add_baggage("user_id".to_string(), "12345".to_string());
        
        assert_eq!(context.get_baggage("user_id"), Some(&"12345".to_string()));
        assert_eq!(context.get_baggage("nonexistent"), None);
    }
    
    #[test]
    fn test_header_propagation() {
        let mut context = TraceContext::new();
        context.add_baggage("user_id".to_string(), "12345".to_string());
        
        let headers = context.to_headers();
        let restored = TraceContext::from_headers(&headers).unwrap();
        
        assert_eq!(context.trace_id.0, restored.trace_id.0);
        assert_eq!(context.span_id.0, restored.span_id.0);
        assert_eq!(restored.get_baggage("user_id"), Some(&"12345".to_string()));
    }
    
    #[test]
    fn test_span_lifecycle() {
        let tracer = Tracer::new("test-service".to_string());
        let mut span = tracer.start_span("test-operation").start();
        
        span.set_tag("http.method", "GET");
        span.log(LogLevel::Info, "Processing request");
        span.set_status(SpanStatus::Ok);
        
        assert_eq!(span.span.tags.get("http.method"), Some(&"GET".to_string()));
        assert_eq!(span.span.logs.len(), 1);
        assert_eq!(span.span.status, SpanStatus::Ok);
    }
    
    #[test]
    fn test_probabilistic_sampler() {
        let sampler = ProbabilisticSampler::new(0.5);
        let trace_id = TraceId::new();
        
        // Should be consistent for the same trace ID
        let decision1 = sampler.should_sample(&trace_id, "test");
        let decision2 = sampler.should_sample(&trace_id, "test");
        assert_eq!(decision1, decision2);
    }
    
    #[test]
    fn test_constant_sampler() {
        let always_sample = ConstantSampler::new(SamplingDecision::Sample);
        let never_sample = ConstantSampler::new(SamplingDecision::NotSample);
        
        let trace_id = TraceId::new();
        
        assert_eq!(always_sample.should_sample(&trace_id, "test"), SamplingDecision::Sample);
        assert_eq!(never_sample.should_sample(&trace_id, "test"), SamplingDecision::NotSample);
    }
    
    #[test]
    fn test_trace_summary() {
        let tracer = Tracer::new("test-service".to_string());
        let span = tracer.start_span("test-operation").start();
        let trace_id = span.span.trace_id.clone();
        
        // Finish the span
        drop(span);
        
        let summary = tracer.get_trace_summary(&trace_id);
        assert!(summary.is_some());
        
        let summary = summary.unwrap();
        assert_eq!(summary.trace_id, trace_id);
        assert_eq!(summary.span_count, 1);
        assert_eq!(summary.error_count, 0);
    }
    
    #[test]
    fn test_service_stats() {
        let tracer = Tracer::new("test-service".to_string());
        let _span1 = tracer.start_span("operation1").start();
        let _span2 = tracer.start_span("operation2").start();
        
        let stats = tracer.get_service_stats();
        assert_eq!(stats.service_name, "test-service");
        assert_eq!(stats.active_spans, 2);
    }
    
    #[test]
    fn test_span_utilities() {
        let mut span = Span::new(
            TraceId::new(),
            SpanId::new(),
            "test-operation".to_string(),
        );
        
        span.set_tag("http.method".to_string(), "GET".to_string());
        assert_eq!(span.get_tag("http.method"), Some(&"GET".to_string()));
        assert_eq!(span.get_tag("nonexistent"), None);
        
        assert!(!span.has_error());
        span.set_status(SpanStatus::Error);
        assert!(span.has_error());
        
        assert!(span.elapsed().is_some());
    }
}