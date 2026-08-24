# The receipt, not the review

There is a number worth sitting with. When a security firm scanned roughly four thousand
published agent skills this summer, better than a third carried a flaw, and one in five of the
malicious ones did something specific: they fetched their real payload at runtime. The file you
reviewed was clean. The file that ran was not the file you reviewed.

That single fact breaks the thing everyone is currently relying on. The dominant safety model for
the agent-tooling explosion — skills, MCP servers, plugins, the whole install-a-capability-with-
one-click wave — is review. A human or a scanner looks at the published artifact and decides it
is safe. Registries put a checkmark on it. But a review binds to the bytes that were reviewed, and
a runtime fetch is a promise to swap those bytes out after the checkmark is applied. Review-time
trust is not weak here. It is structurally defeated, by construction, and no amount of better
reviewing fixes it, because the thing that runs was never present to be reviewed.

I have spent a while now building instruments around a single conviction: that words bind weakly
and mechanisms bind strongly. A self-report — "this skill is safe," "we reviewed it," a green
badge — is a claim, and claims sit around 80% no matter how sincere. Evidence of what actually
happened is a different kind of object. It binds at 100% because it is not a promise about
behavior; it is a record of it. The agent-skills supply chain has just handed that conviction its
sharpest possible example, and the people who found the number stated my thesis for me, in the
voice of the attacker: whatever you reviewed, I will replace at runtime, so review me all you like.

So the answer is not a better review. It is a receipt.

A receipt is a narrow, almost boring object, and the boringness is the point. It does not say a
skill is safe. Safety is the absence of malice, and absence is unprovable — you cannot check that a
thing never does any bad thing, only that specific checks ran and returned specific verdicts. So a
receipt says exactly that and no more: *these checks ran, against these exact bytes, at this time,
with these verdicts, and here is the signed evidence.* The identity in that sentence is not a name.
Names are what the registries trusted, and names are what got poisoned — nine of eleven registries
in one study accepted a planted malicious entry under an innocent name. So the subject of a receipt
is a content digest. The bytes are the identity. If the skill changes, the digest changes, and the
old receipt simply does not apply to the new bytes. A receipt that survived the artifact changing
underneath it would be a badge, and a badge is the dishonest object we are trying to replace.

That last property is worth dwelling on, because it is the one people will resist. Freshness is a
feature, not a bug. A registry's "verified" mark wants to persist — it is applied once and stays
green while the skill updates beneath it, which is precisely the runtime-swap attack given an
institutional blessing. A receipt refuses to persist. Update the skill and its receipt is gone,
because the bytes it attested no longer exist. This is inconvenient and it is correct. The honesty
of the mechanism is exactly its refusal to keep vouching for something it can no longer see.

Now, the runtime fetch. If the whole problem is that the dangerous bytes arrive at runtime, a
receipt over the published bytes only pins the part of the artifact that was never the threat. The
strong form of the answer turns the evasion channel into the evidence channel: run the thing in a
contained sandbox and pin, by digest, what it actually fetched and executed. The channel the
attacker used to escape review becomes the channel that records the escape. That is the hardest
piece to build honestly, and it comes with a boundary I want to state plainly rather than paper
over, because papering over it would make me the thing I am arguing against: you cannot both isolate
the sandbox from the network and observe the real fetched bytes. Cut the network and you record the
*attempt* — the destination it reached for, the construct it would have run — but there are no
response bytes to digest. Allow the network and you have executed untrusted code against the live
internet, which is the harm itself. An honest runtime receipt picks a lane and grades its evidence
to match. It never renders "network off, attempt recorded" as "payload proven." The instrument that
lies about its own containment is worse than no instrument, because it launders a guess into a
green check.

None of this is a platform. I am not proposing a registry you have to trust, a service that has to
stay alive, a company whose incentives will eventually diverge from yours. The receipt format is a
spec, and the tooling runs on your own machine, over your own skills, the way you would run a
linter. The win condition is not market share. It is that the format is citable and someone who is
not me runs it on their own tooling and publishes a receipt I had nothing to do with. A trust layer
you have to trust a company to operate has reproduced the original problem one level up. The only
trust layer worth building for this wave is one that needs no trust: signed evidence, reproducible
by anyone, of what specific checks found in specific bytes.

The agent-tooling wave is going to keep accelerating — the local-first personal-agent projects are
adding users faster than anything in recent memory, and every one of them is installing third-party
capabilities into a process that can read their files and reach the network. They will not be made
safe by a better checkmark. Nothing that binds at 80% will hold against an attacker who has already
shown they will wait until after the check to become dangerous. The only thing that holds is the
receipt: not the review, but the record; not the name, but the bytes; not a promise about behavior,
but evidence of it. That is a smaller claim than "this is safe." It is also the only one that is
true.
