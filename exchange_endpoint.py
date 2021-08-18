from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()

def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """
        
""" Helper Methods (skeleton code for you to implement) """

def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    with open('server_log.txt', 'w') as f:
    	json.dump(msg, f)
    return

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    
    return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
    w3 = Web3()
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys

    return eth_sk, eth_pk
  
def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!

	# If your fill_order function is recursive, and you want to have fill_order return a list of transactions to be filled, 
	# Then you can use the "txes" argument to pass the current list of txes down the recursion
	# Note: your fill_order function is *not* required to be recursive, and it is *not* required that it return a list of transactions, 
	# but executing a group of transactions can be more efficient, and gets around the Ethereum nonce issue described in the instructions
    matched = False
    for existing_oder in txes:
        if existing_oder.buy_currency == order_obj.sell_currency and \
                existing_oder.sell_currency == order_obj.buy_currency:
            if existing_oder.sell_amount / existing_oder.buy_amount >= order_obj.buy_amount / order_obj.sell_amount:
                # If a match is found
                matched = True
                existing_oder.filled = datetime.now()
                order_obj.filled = datetime.now()
                existing_oder.counterparty_id = order_obj.id
                order_obj.counterparty_id = existing_oder.id
                session.commit()
                break

    if matched:
        # If one of the orders is not completely filled
        if existing_oder.sell_amount < order_obj.buy_amount:
            new_order_obj = Order(sender_pk=order_obj.sender_pk, receiver_pk=order_obj.receiver_pk,
                                  buy_currency=order_obj.buy_currency, sell_currency=order_obj.sell_currency,
                                  buy_amount=order_obj.buy_amount - existing_oder.sell_amount,
                                  sell_amount=order_obj.sell_amount - existing_oder.buy_amount,
                                  creator_id=order_obj.id)

        elif order_obj.sell_amount < existing_oder.buy_amount:
            new_order_obj = Order(sender_pk=existing_oder.sender_pk, receiver_pk=existing_oder.receiver_pk,
                                  buy_currency=existing_oder.buy_currency,
                                  sell_currency=existing_oder.sell_currency,
                                  buy_amount=existing_oder.buy_amount - order_obj.sell_amount,
                                  sell_amount=existing_oder.sell_amount - order_obj.buy_amount,
                                  creator_id=existing_oder.id)
        else:
            return
        g.session.add(new_order_obj)
        g.session.commit()
        fill_order(new_order_obj)

  
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

    pass

""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            #Your code here
            return jsonify( eth_pk )
        if content['platform'] == "Algorand":
            #Your code here
            return jsonify( algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        payload = content.get("payload")
        sig = content.get("sig")
        result = check_sig(payload,sig)
        # 2. Add the order to the table
        if result:
            order = content['payload']
            order_obj = Order(sender_pk=order['sender_pk'], receiver_pk=order['receiver_pk'],
                              buy_currency=order['buy_currency'], sell_currency=order['sell_currency'],
                              buy_amount=order['buy_amount'], sell_amount=order['sell_amount'], tx_id=order['tx_id'],
                              signature=content['sig'])
            g.session.add(order_obj)
            g.session.commit()  

        else:
            log_message(payload)
            return jsonify(False)

        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)


        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        orders = [order for order in g.session.query(Order).filter(Order.filled == None).all()]
        fill_order(order_obj, orders)
        
        # 4. Execute the transactions
        
        # If all goes well, return jsonify(True). else return jsonify(False)
        return jsonify(True)

@app.route('/order_book')
def order_book():
	# Same as before
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk" ]
    orders = [order for order in g.session.query(Order).all()]
    data = []
    for existing_oder in orders:
        json_order = {'sender_pk': existing_oder.sender_pk, 'receiver_pk': existing_oder.receiver_pk,
                      'buy_currency': existing_oder.buy_currency, 'sell_currency': existing_oder.sell_currency,
                      'buy_amount': existing_oder.buy_amount, 'sell_amount': existing_oder.sell_amount,
                      'signature': existing_oder.signature}

        data.append(json_order)
    result = {"data": data}
    return jsonify(result)


if __name__ == '__main__':
    app.run(port='5002')
