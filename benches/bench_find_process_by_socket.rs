use criterion::{criterion_group, criterion_main, Criterion};
use sock2proc::find_process_name;

fn run_find_process_by_socket() {
    let dst = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
        80,
    );
    let _process_name = find_process_name(None, Some(dst), sock2proc::NetworkProtocol::TCP);
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("find_process_by_socket", |b| {
        b.iter(|| run_find_process_by_socket())
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
