## `⚠️` Malware Development
<p align="center" width="100%">
    <img width="30%" src="https://user-images.githubusercontent.com/59679082/220690535-7516365f-3383-4385-b7b2-d511d8fb1d17.png"> 
</p>

This repository was created to archive and document all of my attempts to learn and develop malware. I'm brand new to all of this. We'll start from the absolute beginning and see how far we can get. This repository houses the code (often updated to reflect my current "skills" — or lack thereof) from my videos on [YouTube](https://youtube.com/@crr0ww) or my [blog](https://www.crow.rip). 

> [!Important]
> I can't believe this has to be said but I am _not_ a professional developer... _at all_. I will be making _a lot_ of mistakes (as a consequence of my being green to the scene) and I will never claim that any of my code is the best/most efficient or that any of these techniques are things that I've created/discovered. My repeated cringing at my old code has conditioned me to be rather self-conscious of my code and abilities as a whole, but as time progresses, I hope that my coding skills get better and better and that it reflects in this repository. But again, I'm new and learning like all of you were at some point.

The techniques I'd love to learn are:

- `🟢` [Shellcode Injection](https://www.crow.rip/crows-nest/mal/dev/inject/shellcode-injection) 
- `🟢` [DLL Injection](https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection) 
- `🟢` [Using NTDLL](https://www.crow.rip/crows-nest/mal/dev/inject/ntapi-injection) 
- `🟢` [Full NTDLL Implementation](https://www.crow.rip/crows-nest/mal/dev/inject/ntapi-injection/complete-ntapi-implementation)
- `🟢` [Using Direct System Calls](https://www.crow.rip/crows-nest/mal/dev/inject/syscalls/direct-syscalls) 
- `🟢` [Indirect Syscalls](https://www.crow.rip/crows-nest/mal/dev/inject/syscalls/indirect-syscalls)
- ...

> [!Note]
> As I come across more stuff, I'll add more to the list. Moreover, as I complete the techniques above, I'll also update this list. My goal is to populate this repository with a variety of techniques related to process injection, thread hijacking, token-related stuff, kernel-related stuff, evasion-related stuff, etc. etc.

## `📚` Prerequisites
We're going to be dealing with a lot of low-level stuff. As such, it's important to familiarize yourself with languages like `C`, `C++`, `Assembly`, etc. I might create another repository solely for documenting my progression with the aforementioned topics, but that's _far_ back in the pipeline for now.

## `👨‍💻` Compilation
If a technique specifically does _not_ contain a `Makefile`, then it's meant to be compiled using Visual Studio. Otherwise, you can just compile the program(s) with `make`. I'm sure all of these can be compiled with a `Makefile`, but I haven't had the time to give it much attention yet.

> [!Warning]
> Obviously, the stuff in this repository is explicitly for educational purposes. Not that you'll be able to run this in a patched environment (especially with the shellcode generated with `msfvenom` thrown into the mix) without getting the absolute sh*t flagged out of it. Regardless, I do not condone the use of these programs for any malicious activities. 

## `🛑` Common Pitfalls
Since there has been a lot of attention on the videos and thus, a ton of people trying out the techniques for themselves, a _lot_ of problems have been encountered. However, they're all (mostly) very easy to diagnose and remedy.
#### Crashing Process
- If a process is crashing, make sure that the architecture that you compiled your program in **matches** the architecture of the target process you're trying to inject into. This is the single most common pitfall I see when diagnosing/viewing someone's issues with their program and it can be _very_ annoying and tedious.
- A crashing process could also be indicative of some incomplete/missing/borked shellcode, so make sure your shellcode didn't get cut out halfway during copying and pasting it.
- This could also be a consequence of _how_ you're generating your payload. Make sure to explicitly define `EXITFUNC=thread` during your `msfvenom` generation which will allow the process to exit gracefully instead of shredding the process and killing it. The included shellcode already has this set, so if you're facing the crashing issue, that would need further investigation.
- On a slight tangent, if you're injecting a process and _nothing_ is happening — it's not even crashing, then, this again, could be a consequence of an architectural mismatch or borked shellcode.
#### Interference
- A look into Windows Defender might be warranted since it can also interfere with our program's execution, so make sure to set exclusions accordingly.
- You get a reverse shell or something after injecting a remote target process and for the first few seconds, it's fine. Then, the second you issue a command, Windows Defender (or some other security solution) kills your process/connection. This can be due to how signatured (`msfvenom` | `metasploit`) payloads, listeners, handlers, etc. are. Encrypt your traffic or use something less signatured. A reverse shell by itself is almost always suspicious so more techniques are going to be needed in conjunction with what we've learned above.
- The (in)direct syscalls technique isn't working! This could be due to API Hooking. EDRs/security solutions will sometimes inject their own DLL into your process to hook commonly abused functions. The function(s) responsible for scraping the [syscall numbers](https://github.com/cr-0w/maldev/blob/dev/Direct%20Syscalls/injection.c#L11-L29) and [instructions](https://github.com/cr-0w/maldev/blob/dev/Indirect%20Syscalls/injection.c#L11-L42) currently don't incorporate a way to fight/circumnavigate API Hooking and will fall apart due to the offsets being borked. So, you're going to have to be stuck in limbo for a while and research how to do that yourself. Eventually (TM), I'll add a way to account for hooks, in which case, I'll just remove this line from the common pitfalls section. 

## `🫂` Contributing
I'm only going to be accepting bug fixes or typo fixes. Since this repository was created to document my personal growth with malware development, I don't want to cheat myself by having you contribute a technique which I myself am not currently capable of implementing. If I'm doing something super inefficently (which most of the time I am), then depending on what it is, it _might_ get accepted as a pull request. Either way, contributions are accepted based on those two (`2`) conditions. Thank you very much to everyone who helps out!

## `💖` Acknowledgements
I'd be nothing without the support and research of my incredible (and insanely smart) friends who've pretty much taught me everything I know — in some way or another, as well as directly influenced me on this ongoing and amazing journey. In no particular order, thanks to:
- [`Lavender`](https://github.com/Lavender-exe), [`Zetty`](https://github.com/Z3tty), [`Xor`](https://github.com/x0reaxeax), [`Spider`](https://twitter.com/C5pider), [`Rektsu`](https://twitter.com/rektsu1337), [`Bakki`](https://twitter.com/shubakki), [`Nigerald`](https://twitter.com/d_tranman), [`Snow`](https://twitter.com/never_unsealed), `Aqua`, [`Geistmeister`](https://twitter.com/tomiesghost_), [`Urien`](https://twitter.com/Uri3n), and many _many_ more.
