
def ws_message(message, app_id):
    # ASGI WebSocket packet-received and send-packet message types
    # both have a "text" key for their textual data.
    message.reply_channel.send({
        "text": message.content['text ' + str(app_id)],
    })
