cov:
	cargo +nightly fuzz coverage combo
	mv coverage/combo/coverage.profdata target/coverage.profraw
	grcov target/coverage.profraw \
		--binary-path target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/combo \
		--source-dir ../sbat \
		--output-types html \
		--output-path ../cov_report

.PHONY: cov
