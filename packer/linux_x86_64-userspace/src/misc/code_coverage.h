#pragma once

// Needs to be called before each RELEASE
void update_perm_trace_buffer(void);

// Should be called once before taking the snapshot
void start_coverage(void);

// Should be called every X iterations to regularly update coverage
void update_coverage_dump(void);
