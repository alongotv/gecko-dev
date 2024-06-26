# List of Fenix Threads

To profile background threads using the Firefox Profiler, you need to specify their names. It uses a case-insensitive substring match, e.g. specifying `default` will match all threads in the kotlin default dispatcher which have a name like, `DefaultDispatcher-worker-*`. This document is a list of the threads in fenix (via `ThreadGroup.list()` as of Mar 2022) to make using this functionality easier:
```
AutoSave-thread-1
BrowserIcons-thread-1
BrowserIcons-thread-2
BrowserIcons-thread-3
BrowserStore-thread-1
ConnectivityThread
DefaultDispatcher-worker-1
DefaultDispatcher-worker-2
DefaultDispatcher-worker-3
DefaultDispatcher-worker-4
DefaultDispatcher-worker-5
DefaultDispatcher-worker-6
DefaultDispatcher-worker-7
DefaultDispatcher-worker-8
FinalizerDaemon
FinalizerWatchdogDaemon
FxaAccountManager-thread-1
Gecko
GeckoInputConnection
GleanAPIPool
HeapTaskDaemon
HistoryMetadataService-thread-1
LeakCanary-Heap-Dump
NimbusDbScope-thread-1
NimbusFetchScope-thread-1
PlacesStorageWriteScope-thread-1
ReferenceQueueDaemon
ThumbnailStorage-thread-1
ThumbnailStorage-thread-2
ThumbnailStorage-thread-3
WM.task-1
WM.task-2
WM.task-3
WM.task-4
androidx.work-1
androidx.work-2
arch_disk_io_0
arch_disk_io_1
arch_disk_io_2
arch_disk_io_3
glean.MetricsPingScheduler
main
pool-23-thread-1
pool-9-thread-1
pool-9-thread-2
queued-work-looper
```

Note that `arch_disk_io_*` represents the kotlin io dispatcher.
