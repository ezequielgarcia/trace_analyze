# trace_analize.py

This script allows to perform some analysis on kernel dynamic memory allocations by post-processing ftrace kmem event.
In adition, it can also report on static footprint on a built kernel tree.

trace_analyze.py typically needs access to: a built kernel tree and an ftrace kmem log.

Since reading the kmem event log is a costly operation, you can also generate a 'db' file to speed-up 
subsequent runs of the script.

This script and work related has been done thanks to the CEWG project [Kernel dynamic memory allocation tracking and reduction](http://elinux.org/Kernel_dynamic_memory_allocation_tracking_and_reduction).
You can find lot more information about this script and about kernel dynamic memory tracking [here](http://elinux.org/Kernel_dynamic_memory_analysis)

### Feedback

trace_analyze.py is not stable, so expect some roughness. Testing and feedback is welcome.
If you have any questions, feedback or praises to make, just open a github issue.

## Using trace_analyze.py for static analysis

Usage is fairly simple

    $ ./trace_analyze.py -k /usr/src/linux -r foo.png
    $ ./trace_analyze.py --kernel /usr/src/linux --rings-file foo.png

This should produce a ringchart png file in the current directory.
Of course, you can use absolute and relative paths in the path parameter

    $ ./trace_analyze.py -k ../../torvalds -r foo.png

If you're interested in a specific subsystem you can use a parameter to specify
the directory tree branch to take as root

    $ ./trace_analyze -k linux --start-branch fs/ext2 -r ext2.png
    $ ./trace_analyze -k linux -b drivers -r drivers.png
    $ ./trace_analyze -k linux -b mm -r mm.png

Each of this commands will produce a ringchart png file in the
curent directory, named as specified.

### Under the hood

The script will perform a directory walk, internally creating a tree matching
the provided kernel tree. On each object file found (like fs/inode.o) it will
perform a 'readelf --syms' to get a list of symbols contained in it. Nothing fancy.

## Using trace_analyze.py for dynamic analysis

### Producing a kmem trace log file 

In case you don't know or don't remember how to use ftrace to produce kmem events, here's a little remainder.
For more information, please refer to the canonical trace documentation at the linux tree:

- Documentation/trace/ftrace.txt
- Documentation/trace/tracepoint-analysis.txt
- and everything else inside Documentation/trace/

The purpose of trace_analyze script is to perform dynamic memory analysis.
For this to work you need feed it with a kmem trace log file (of course, you also need to give hime a built kernel tree).

Such log must be produced on the running target kernel, but you can post-process it off-box.
For instance, you boot your kernel with kmem parameters to enable ftrace kmem events:
(it's recommended to enable all events, despite not running a NUMA machine).

    kmem="kmem:kmalloc,kmem:kmalloc_node,kmem:kfree,kmem:kmem_cache_alloc,kmem:kmem_cache_alloc_node,kmem:kmem_cache_free"

This parameter will have linux to start tracing as soon as possible. Of course some early traces will be lost, see below.

(on your target kernel)

    # To stop tracing
    $ echo "0" > /sys/kernel/debug/tracing/tracing_on
    # Dump 
    $ cat /sys/kernel/debug/tracing/trace > kmem.log

Now you need to get this file so you can post-process it using trace_analyze.py.
In my case, I use qemu with a file backing serial device, so I simply do:

(on your target kernel)

    $ cat /sys/kernel/debug/tracing/trace > /dev/ttyS0

And I get the log on qemu's backing file.

Now you have everything you need to start the analysis.

### Slab accounting file output

To obtain a memory accounting file you need to use --acount-file (-c) parameter, like this:

    $ ./trace_analyze.py -k linux -f kmem.log --account-file account.txt
    $ ./trace_analyze.py -k linux -f kmem.log -c account.txt

This will produce an account file like this:

    current bytes allocated:     669696
    current bytes requested:     618823
    current wasted bytes:         50873
    number of allocs:              7649
    number of frees:               2563
    number of callers:              115
     
     total    waste      net alloc/free  caller
    ---------------------------------------------
    299200        0   298928  1100/1     alloc_inode+0x4fL
    189824        0   140544  1483/385   __d_alloc+0x22L
     51904        0    47552   811/68    sysfs_new_dirent+0x4eL
     16384     8088    16384     1/0     __seq_open_private+0x24L
     15936     1328    15936    83/0     device_create_vargs+0x42L
     14720    10898    14016   460/22    sysfs_new_dirent+0x29L

### Controlling account output

You can tell the script to read only kmalloc events (notice the option name is *--malloc*):

    $ ./trace_analyze.py -k linux -f kmem.log -c account.txt --malloc

Or you can tell the script to read only kmem_cache events:

    $ ./trace_analyze.py -k linux -f kmem.log -c account.txt --cache
   
If you want to order the account file you can use --order-by (-o):

    $ ./trace_analyze.py -k linux -f kmem.log -c account.txt --order-by=waste
    $ ./trace_analyze.py -k linux -f kmem.log -c account.txt --malloc -o waste

The possible options for order-by parameter are:

* total_dynamic: Added allocations size
* current_dynamic: Currently allocated size
* alloc_count: Number of allocations
* free_count: Number of frees
* waste: Currently wasted size

You can pick a directory to get an account file showing only the allocations from that directory.
This is done with the --start-branch (-b) option, just like we've done for the static analysis:

    $ ./trace_analyze.py -k linux -f kmem.log -c account.txt -b drivers/base/

All of these options can be combined. For instance, if you want to get kmalloc events only,
coming from fs/ directory and ordered by current dynamic footprint:

    $ ./trace_analyze.py -k linux -f kmem.log -b fs -c account.txt -o current_dynamic --malloc

### Producing a pretty ringchart for dynamic allocations

As already explained in the static analysis section, it's possible to produce
a ringchart to get **the big picture** of dynamic allocations.
You will need to have *matplotlib* installed, which should be as easy as:

    $ {your_pkg_manager} install matplotlib

The script usage is very simple, just pass the parameter --rings-file (-r) along with a filename

    $ ./trace_analyze.py -k linux -f kmem.log --rings-file=dynamic.png

This command will produce a png file named as specified.
The plot will show current dynamic allocations by default.
You can control the used attrbute used for the ringchar plot using --rings-attr (-a) parameter.

The available options are:

- current: static + current dynamic size
- static: static size
- waste: wasted size
- current_dynamic: current dynamic size
- total_dyamic: added dynamic size

For instance, you may want a ringchart for wasted bytes

    $ ./trace_analyze.py -k linux -f kmem.log -r -a waste

You can use --start-branch (-b) parameter to plot allocations made from just one directory.
For instance, if you want to get wasted bytes for ext4 filesystem:

    $ ./trace_analyze.py -k ../torvalds -f kmem.log -r ext4_waste.png -a waste -b fs/ext4

Or, if you want to see static footprint of arch-dependent mm code:

    $ ./trace_analyze.py -k ../torvalds -f kmem.log -r x86_static.png -a static -b arch/x86/mm

Also, you can filter kmalloc or kmem_cache traces using either --malloc, or --cache:

    $ ./trace_analyze.py -k linux/ -f boot_kmem.log -r kmallocs.png --malloc

#### Pitfall: wrongly reported allocation (and how to fix it)

There are a number of functions (kstrdup, kmemdup, krealloc, etc) that do
some kind of allocation on behalf of its caller.

Of course, we don't want to get trace reports from these functions,
but rather from its caller. To acomplish this, we must use a variant
of kmalloc, called kmalloc_track_caller, which does exactly that.

Let's see an example. As of today kvasprintf() implementation looks
like this

    (see lib/kasprintf.c:14)
    char *kvasprintf(gfp_t gfp, const char *fmt, va_list ap)
    {
   	   /* code removed */
	   p = kmalloc(len+1, gfp); 

And trace_analyze produces the account file 

    total    waste      net alloc/free  caller
    ---------------------------------------------
    2161     1184     2161   148/0     kvasprintf

The source of this 148 allocations may be a single caller,
or it may be multiple callers. We just can't know.
However, if we replace kmalloc with kmalloc_track_caller,
we're going to find that out.

    char *kvasprintf(gfp_t gfp, const char *fmt, va_list ap)
    {
           /* code removed */
           p = kmalloc_track_caller(len+1, gfp);

After running the re-built kernel, and comparing both current
and previous account files, we find this is the real caller:

    total    waste      net alloc/free  caller
    ---------------------------------------------
    2161     1184     2161   148/0     kobject_set_name_vargs

So, we've accurately tracked this allocation down to the kobject code.

## Using a DB file to speed-up multiple runs

You may find yourself analyzing a large kmem log file. Probably, you want to run the script
several times to get different kinds of results.

The script is not very clever and will re-read the long kmem file on each run.
To alleviate this problem you can have trace_analyze.py create a so-called DB file,
and use this file instead of the kmem log file on subsequent runs.

This is done using the --save-db and --db-file parameters. Like this

    $ ./trace_analyze.py -k ../torvalds/ -f kmem.log --save-db db

Notice you should create the DB file without any filters, like --malloc or --start-branch,
in order to save the full kmem event log.

Once you have the **db** file created, you would use it on each run

    $ ./trace_analyze.py -k ../torvalds/ --db-file db -r rings.png -c account.txt

Hopefully, this would prevent you from cursing trace_analyze for being so slow.

