# Morph Module:  A Linux LKM for altering setuid behavior

### Why?

If I have a reason, I'm not allowed to share it ... but mostly I was just curious. Here's a very diluted example...

Suppose you worked in an environment with hundreds of servers and a handful of administrators with root access. Then suppose you had thousands of system-level users. Inevitably an application team comes along, providing some piece of intrastructure that requires access to a subset of those system-level users, but the administrators (rightfully) will not grant them root access...so setuid-family system calls will not suffice to alter the context/credentials of a process (from within the process itself). Instead the administrators start maintaining sudo rules consisting of huge lists of users. 

It starts getting hairy.

Now the developers of these infrastructure-type-processes have some daemon running as a generic service account, and lets say it's receiving data over the network, and now they want to write it out to the file system. But they don't want to just write it out as their generic service account that owns that daemon, they want to write it out as one of a thousand other system-level users. But they can't just setuid()...etc..., they've got to fork(), exec(), invoke sudo and tell it to do something with that data their service just received...and they do it a lot. It's slow, and the sudo rules are a huge administrative burden.

So the problem is...how do you grant non-root users access to other non-root users (for purposes of both process accounting and file-system access) in the most efficient manner possible?

I thought...maybe you hook the `setuid()` system call. I'm not saying it's a good idea...but it's an idea...and the performance ended up being very, very good (like 7400% faster than fork/exec/sudo for my "many small writes to a file" example).

### Your Feedback / Code Review / Contributions

Maybe the idea is not stellar, and the security implications are great. Not looking to argue those points.

If you know a better way to solve this problem, I'd love to hear your feedback.

If you can improve the code (I'm sure you can), I'd love to see how you'd make it better.

### Building / Loading

First of all, locating the address of the system call table is essential. If you have the wrong address, you'll simply crash your system when you load this module.

You may be able to find the address on your system as follows:

`grep ' sys_call_table' /boot/System.map-$(uname -r) | cut -f1 -d' '`

or

`cat /proc/kallsyms | grep "R sys_call_table" | cut -f1 -d' '`

Edit morph_module.c and update `SYS_CALL_TABLE_ADDRESS`.

`make`
`insmod morph_module.ko`

Have a look at `dmesg | tail -10` for output.

### Rules

Rules are expressed very simply:

`LHS=RHS`

Where `LHS` or `RHS` may be a single integer (ex. 100), a comma-seperated list of integers (ex. 100,200,300), or a hypenated range of integers (ex. 100-300). `LHS` represents the effective-UID where access is being permitted /from/, while `RHS` represents the real-,effective-,saved-,fs- UID access is permitted /to/.

White-space delimits multiple rules.

Construct your rules and echo them into /proc/morph_rules:

`echo "100,200,1000-9999=50 100,200=60,70-80" > /proc/morph_rules`

These new rules will take effect immediately, obviating any previous rules.
