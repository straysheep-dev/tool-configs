# Titus Rule Files

[Titus](https://github.com/praetorian-inc/titus) is a fast secrets scanner that can ingest custom rule files. [The existing rule files](https://github.com/praetorian-inc/titus/tree/main/pkg/rule/rules) can be used as reference to build your own.

> [!TIP]
> There's no reason why custom rules can't be used to do threat hunting and source code review.

## Notes & TODO

There's currently no good way to filter matches based on a priority. In other words, ignore base64 matches, if the same string matches an email pattern.

For now, it's better to have false positives than false negatives. We can sift through the noise using `titus explore`. TODO: Review using the [scoring mechanism](https://github.com/praetorian-inc/titus/tree/main#finding-scoring) for this.

## License

All [bstrings](https://github.com/EricZimmerman/bstrings/blob/master/LICENSE.md) patterns are under the same [MIT license](../LICENSE).

Patterns used to validate alternate IPv4 address representations were derived from [this SANS ISC diary by Johannes Ullrich](https://isc.sans.edu/diary/Adventures%20in%20Validating%20IPv4%20Addresses/30348), and built with the help of `claude-sonnet-5`, after reviewing my existing [`check-strings.sh`](https://github.com/straysheep-dev/linux-configs/blob/main/check-strings.sh).

This project adheres to the [Linux Kernel developer guidance on using AI coding assistants](https://docs.kernel.org/process/coding-assistants.html).

Drafts, examples, and research generated using [Claude](https://claude.com/product/overview), both in the web interface and via [Claude Code](https://code.claude.com/docs/en/overview), after ingesting any existing files and reviewing the direction in a [CLAUDE.md](https://github.com/straysheep-dev/agent-configs) file or user prompt.

```
Assisted-by: Claude:claude-sonnet-5

Assisted-by: OpenAI:gpt-4o

Assisted-by: OpenAI:o1-mini

```
