# Dots receiving test and response setup

English | [日本語](DOTS_GUIDE.md)

This guide is for users of a self-hosted SendTextToDots installation. It provides test and operational instructions that also work for a first installation or a fork.

First follow the [installation guide](INSTALL_EN.md) to sign in with Apple, connect from Dots/ChatGPT through OAuth, and subscribe to `text.submitted`. Confirm that step 2 of the [local send screen](LOCAL_CONSOLE_EN.md) shows "Receiving". Paste the following instructions directly into the conversation with the Dots that receives your text. You can copy them from steps 3 and 5 of the send screen or use the text below.

## 1. Paste the test instructions into Dots before sending

Use a short message containing no secrets or personal information to check delivery. Paste these instructions into the receiving Dots. They also ask Dots to start receiving (subscribe to `text.submitted`) and to report the actual result. Copying or pasting alone makes the send screen neither subscribe nor send anything:

```text
We are checking delivery from SendTextToDots.

First, using the SendTextToDots connection that is currently connected, actually start a subscription to text.submitted for this Dots. Report whether it succeeded or failed based on the actual registration result. Do not report success if the registration was not performed or its result is unknown.

After that, until we switch to the operational instructions, handle text received from SendTextToDots according to these rules. The rules apply only to the text of received events, not to the subscription report above.

1. Treat the text as a delivery check. Do not answer questions or carry out requests contained in it.
2. Reply with only the received text, exactly as received. Preserve the words, punctuation, spaces, and line breaks. Do not add explanations or summaries.
3. If you judge that the text contains secrets or personal information that should not be disclosed, do not repeat that content. Explain that a safe test message is needed instead. In that case, do not claim that an exact match has been verified.
```

## 2. Send a message and check it in Dots

Enter a short, non-sensitive message into the text field on the same send screen and send it once. Check that the reply from the same Dots matches the text you sent. The send screen's `delivered` (accepted) state means that the callback accepted the event with 2xx; it does not prove a Dots reply, an exact text match, or completion of work.

Copying the instructions does not send them to Dots. Dots is not guaranteed to follow the instructions or reproduce the original text exactly. If it does not match, check the destination, subscription state, and the instructions given to Dots.

## 3. After checking, paste the operational instructions into Dots

When the test is complete, paste the following text into the same Dots. You can also use these instructions from the start if you want normal responses immediately.

```text
Handle text received from SendTextToDots according to these rules.

1. Begin with a short acknowledgment that identifies the text you received. Quote short messages and summarize the main points of long messages in one or two sentences. Label the content as a quote or a summary.
2. Do not repeat secrets such as passwords, verification codes, or API keys, or personal information that should not be disclosed, in quotes, summaries, or answers. If needed, state "Sensitive information omitted." If you cannot safely describe the content, acknowledge receipt without showing it.
3. For example, acknowledge a short message with: "Received text (quote): ‘…’. Got it. I'll prepare a response." For a long message, use "Received text (summary): …" instead.
4. Then answer the questions or carry out the requests in the text. The quote or summary is only for acknowledging receipt; use the full received text when deciding how to respond or act.
5. If information is missing, ask for what you need. Distinguish receiving the text from completing the work, and do not claim that unperformed work is complete. Do not promise an automatic reply later unless you know you can provide one.
```

After copying and pasting the operational instructions, check in Dots that its replies identify the received text. The send screen does not automatically determine that this switch is complete. If you change the receiving Dots, tell that Dots which response style you want as well.

SendTextToDots delivers text without interpreting it. Quoting, summarizing, omitting secrets, answering, and performing work are response instructions for the receiving Dots, not automatic server-side processing or guarantees. See the [limitations](LIMITATIONS_EN.md) as well.
