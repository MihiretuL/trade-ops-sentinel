"""Deterministic in-memory price-time priority limit order book.

This matching engine is a local digital twin for demonstrations and testing. It
is not exchange connectivity, market data, or a production execution venue.
All prices and notionals use Decimal; price levels are ordered by price and FIFO
within a price level.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

from .fix_protocol import build_fix_message, parse_fix_message


@dataclass
class RestingOrder:
    cl_ord_id: str
    symbol: str
    side: str
    quantity: Decimal
    leaves_qty: Decimal
    limit_price: Decimal
    timestamp_index: int
    cum_qty: Decimal = Decimal("0")
    notional: Decimal = Decimal("0")


@dataclass(frozen=True)
class FIXFrame:
    direction: str
    raw_fix: str


@dataclass
class MatchingResult:
    cl_ord_id: str
    symbol: str
    side: str
    order_qty: Decimal
    limit_price: Decimal
    cum_qty: Decimal
    leaves_qty: Decimal
    average_price: Decimal
    status: str
    exec_type: str
    rejected: bool
    rejection_reason: str | None
    frames: list[FIXFrame]
    fills: list[dict[str, Any]] = field(default_factory=list)

    @property
    def notional(self) -> Decimal:
        return self.cum_qty * self.average_price


class LimitOrderBook:
    """Six-symbol LOB with five seeded levels on each side and FIX 4.2 output."""

    MARKET: dict[str, tuple[Decimal, Decimal]] = {
        "AAPL": (Decimal("225.50"), Decimal("0.01")),
        "NVDA": (Decimal("138.40"), Decimal("0.05")),
        "MSFT": (Decimal("415.20"), Decimal("0.01")),
        "SPY": (Decimal("580.10"), Decimal("0.01")),
        "TSLA": (Decimal("245.00"), Decimal("0.05")),
        "ESZ6": (Decimal("6000.00"), Decimal("0.25")),
    }

    def __init__(self, *, initialize_liquidity: bool = True, venue: str = "EXCHANGE_GW") -> None:
        self.venue = venue
        self._bids: dict[str, dict[Decimal, deque[RestingOrder]]] = defaultdict(dict)
        self._asks: dict[str, dict[Decimal, deque[RestingOrder]]] = defaultdict(dict)
        self._orders: dict[str, RestingOrder] = {}
        self._order_states: dict[str, MatchingResult] = {}
        self._last_trade: dict[str, Decimal | None] = {symbol: None for symbol in self.MARKET}
        self._clord_counter = 0
        self._exec_counter = 0
        self._out_seq = 0
        self._in_seq = 0
        self._time_priority = 0
        if initialize_liquidity:
            self.seed_liquidity()

    def seed_liquidity(self) -> None:
        """Seed exactly five two-sided levels per supported symbol."""
        for symbol, (mid, tick) in self.MARKET.items():
            bids = self._bids[symbol]
            asks = self._asks[symbol]
            for level in range(1, 6):
                bid_price = mid - tick * level
                ask_price = mid + tick * level
                bids.setdefault(bid_price, deque()).append(self._liquidity_order(symbol, "BUY", bid_price, Decimal(100 * (6 - level))))
                asks.setdefault(ask_price, deque()).append(self._liquidity_order(symbol, "SELL", ask_price, Decimal(100 * (6 - level))))

    def _liquidity_order(self, symbol: str, side: str, price: Decimal, qty: Decimal) -> RestingOrder:
        self._time_priority += 1
        return RestingOrder(f"BOOK-{symbol}-{side}-{price}", symbol, side, qty, qty, price, self._time_priority)

    @staticmethod
    def _decimal(value: Decimal | str | int) -> Decimal:
        try:
            result = value if isinstance(value, Decimal) else Decimal(str(value))
        except InvalidOperation as exc:
            raise ValueError(f"Invalid decimal value {value!r}") from exc
        if not result.is_finite():
            raise ValueError("Order price and quantity must be finite")
        return result

    def _new_clord_id(self) -> str:
        self._clord_counter += 1
        return f"ORD-{self._clord_counter:08d}"

    def _next_seq(self, direction: str) -> int:
        if direction == "outbound":
            self._out_seq += 1
            return self._out_seq
        self._in_seq += 1
        return self._in_seq

    def _frame(self, direction: str, msg_type: str, fields: list[tuple[int, str]]) -> FIXFrame:
        sender, target = ("WEX_DMA", self.venue) if direction == "outbound" else (self.venue, "WEX_DMA")
        sequence = self._next_seq(direction)
        wire = build_fix_message(
            [(35, msg_type), (34, str(sequence)), (49, sender), (56, target), *fields],
            begin_string="FIX.4.2",
        )
        parse_fix_message(wire)
        return FIXFrame(direction=direction, raw_fix=wire)

    def _report(
        self,
        clord: str,
        symbol: str,
        side: str,
        order_qty: Decimal,
        limit: Decimal,
        cum: Decimal,
        leaves: Decimal,
        average: Decimal,
        *,
        status: str,
        exec_type: str,
        order_id: str,
        last_qty: Decimal = Decimal("0"),
        last_px: Decimal = Decimal("0"),
        orig_clord: str | None = None,
        reject_reason: str | None = None,
    ) -> FIXFrame:
        fields: list[tuple[int, str]] = [(11, clord), (37, order_id), (150, exec_type), (39, status),
            (55, symbol), (54, "1" if side == "BUY" else "2"), (38, str(order_qty)),
            (14, str(cum)), (151, str(leaves)), (6, str(average))]
        if orig_clord:
            fields.append((41, orig_clord))
        if exec_type in {"1", "2"}:
            self._exec_counter += 1
            fields.extend([(17, f"EXEC-{self._exec_counter:010d}"), (32, str(last_qty)), (31, str(last_px))])
        if reject_reason is not None:
            fields.extend([(103, "3"), (58, reject_reason)])
        return self._frame("inbound", "8", fields)

    def _best_price(self, symbol: str, side: str) -> Decimal | None:
        book = self._asks[symbol] if side == "BUY" else self._bids[symbol]
        prices = [price for price, queue in book.items() if queue]
        if not prices:
            return None
        return min(prices) if side == "BUY" else max(prices)

    def _mid_price(self, symbol: str) -> Decimal:
        best_bid = self._best_price(symbol, "SELL")
        best_ask = self._best_price(symbol, "BUY")
        if best_bid is None or best_ask is None:
            return self.MARKET[symbol][0]
        return (best_bid + best_ask) / Decimal("2")

    def match_new_order(
        self,
        symbol: str,
        side: str,
        order_qty: Decimal | str | int,
        limit_price: Decimal | str,
        *,
        cl_ord_id: str | None = None,
        msg_seq_num: int | None = None,
        orig_cl_ord_id: str | None = None,
    ) -> MatchingResult:
        """Submit an order, apply a 5% risk collar, match by price-time priority, emit FIX 4.2."""
        symbol = symbol.upper()
        side = side.upper()
        if symbol not in self.MARKET:
            raise ValueError(f"Unsupported symbol {symbol!r}; supported: {', '.join(self.MARKET)}")
        if side not in {"BUY", "SELL"}:
            raise ValueError("side must be BUY or SELL")
        quantity, limit = self._decimal(order_qty), self._decimal(limit_price)
        if quantity <= 0 or limit <= 0:
            raise ValueError("order_qty and limit_price must be greater than zero")
        clord = cl_ord_id or self._new_clord_id()
        order_id = f"EX-{clord}"
        frames: list[FIXFrame] = []
        outgoing_seq = msg_seq_num if msg_seq_num is not None else self._next_seq("outbound")
        if msg_seq_num is not None:
            self._out_seq = max(self._out_seq, msg_seq_num)
        order_type = "G" if orig_cl_ord_id else "D"
        outbound_fields = [(11, clord), (55, symbol), (54, "1" if side == "BUY" else "2"),
                           (38, str(quantity)), (40, "2"), (44, str(limit))]
        if orig_cl_ord_id:
            outbound_fields.insert(1, (41, orig_cl_ord_id))
        sender, target = "WEX_DMA", self.venue
        outbound_wire = build_fix_message(
            [(35, order_type), (34, str(outgoing_seq)), (49, sender), (56, target), *outbound_fields],
            begin_string="FIX.4.2",
        )
        parse_fix_message(outbound_wire)
        frames.append(FIXFrame("outbound", outbound_wire))

        mid = self._mid_price(symbol)
        if abs(limit - mid) / mid > Decimal("0.05"):
            reject = self._report(clord, symbol, side, quantity, limit, Decimal(0), quantity, Decimal(0),
                                  status="8", exec_type="8", order_id=order_id, reject_reason="OrderExceedsLimit")
            frames.append(reject)
            result = MatchingResult(clord, symbol, side, quantity, limit, Decimal(0), quantity, Decimal(0),
                                    "8", "8", True, "OrderExceedsLimit", frames)
            self._order_states[clord] = result
            return result

        frames.append(self._report(clord, symbol, side, quantity, limit, Decimal(0), quantity, Decimal(0),
                                   status="0", exec_type="0", order_id=order_id, orig_clord=orig_cl_ord_id))
        remaining = quantity
        cum = Decimal(0)
        notional = Decimal(0)
        fills: list[dict[str, Any]] = []
        opposite = self._asks[symbol] if side == "BUY" else self._bids[symbol]
        prices = sorted(opposite, reverse=side == "SELL")
        for price in prices:
            marketable = price <= limit if side == "BUY" else price >= limit
            if not marketable or remaining <= 0:
                break
            queue = opposite[price]
            while queue and remaining > 0:
                resting = queue[0]
                fill_qty = min(remaining, resting.leaves_qty)
                remaining -= fill_qty
                cum += fill_qty
                notional += fill_qty * price
                resting.cum_qty += fill_qty
                resting.notional += fill_qty * price
                resting.leaves_qty -= fill_qty
                fills.append({
                    "maker_cl_ord_id": resting.cl_ord_id,
                    "symbol": symbol,
                    "side": "SELL" if side == "BUY" else "BUY",
                    "quantity": fill_qty,
                    "price": price,
                    "timestamp_index": resting.timestamp_index,
                })
                self._last_trade[symbol] = price
                average = notional / cum
                final = remaining == 0
                status, exec_type = ("2", "2") if final else ("1", "1")
                frames.append(self._report(clord, symbol, side, quantity, limit, cum, remaining, average,
                                           status=status, exec_type=exec_type, order_id=order_id,
                                           last_qty=fill_qty, last_px=price, orig_clord=orig_cl_ord_id))
                maker_state = self._order_states.get(resting.cl_ord_id)
                if maker_state is not None:
                    maker_average = resting.notional / resting.cum_qty
                    maker_status, maker_exec_type = ("2", "2") if resting.leaves_qty == 0 else ("1", "1")
                    maker_frame = self._report(
                        resting.cl_ord_id, symbol, resting.side, resting.quantity, resting.limit_price,
                        resting.cum_qty, resting.leaves_qty, maker_average,
                        status=maker_status, exec_type=maker_exec_type,
                        order_id=f"EX-{resting.cl_ord_id}", last_qty=fill_qty, last_px=price,
                    )
                    frames.append(maker_frame)
                    maker_state.cum_qty = resting.cum_qty
                    maker_state.leaves_qty = resting.leaves_qty
                    maker_state.average_price = maker_average
                    maker_state.status = maker_status
                    maker_state.exec_type = maker_exec_type
                    maker_state.frames.append(maker_frame)
                if resting.leaves_qty == 0:
                    queue.popleft()
            if not queue:
                opposite.pop(price, None)

        average = notional / cum if cum else Decimal(0)
        if remaining > 0:
            self._time_priority += 1
            resting_order = RestingOrder(clord, symbol, side, quantity, remaining, limit, self._time_priority)
            own = self._bids[symbol] if side == "BUY" else self._asks[symbol]
            own.setdefault(limit, deque()).append(resting_order)
            self._orders[clord] = resting_order
            status, exec_type = ("1", "1") if cum else ("0", "0")
        else:
            status, exec_type = "2", "2"
        result = MatchingResult(clord, symbol, side, quantity, limit, cum, remaining, average,
                                status, exec_type, False, None, frames, fills)
        self._order_states[clord] = result
        return result

    def cancel_order(self, cl_ord_id: str) -> MatchingResult:
        """Cancel a resting order; a fill-completed order receives TooLateToCancel."""
        previous = self._order_states.get(cl_ord_id)
        if previous is None:
            raise KeyError(f"Unknown ClOrdID {cl_ord_id!r}")
        frames = [self._frame("outbound", "F", [(11, f"CXL-{cl_ord_id}"), (41, cl_ord_id),
                                                       (55, previous.symbol), (54, "1" if previous.side == "BUY" else "2"),
                                                       (38, str(previous.order_qty))])]
        if previous.leaves_qty == 0 and previous.cum_qty > 0:
            fields = [(11, f"CXL-{cl_ord_id}"), (41, cl_ord_id), (37, f"EX-{cl_ord_id}"), (39, "2"),
                      (434, "1"), (102, "0"), (58, "TooLateToCancel")]
            frames.append(self._frame("inbound", "9", fields))
            return MatchingResult(previous.cl_ord_id, previous.symbol, previous.side, previous.order_qty,
                                  previous.limit_price, previous.cum_qty, Decimal(0), previous.average_price,
                                  "2", previous.exec_type, False, "TooLateToCancel", frames)
        resting = self._orders.pop(cl_ord_id, None)
        if resting is None:
            fields = [(11, f"CXL-{cl_ord_id}"), (41, cl_ord_id), (37, f"EX-{cl_ord_id}"), (39, previous.status),
                      (434, "1"), (102, "1"), (58, "Unknown or non-resting order")]
            frames.append(self._frame("inbound", "9", fields))
            return MatchingResult(previous.cl_ord_id, previous.symbol, previous.side, previous.order_qty,
                                  previous.limit_price, previous.cum_qty, previous.leaves_qty, previous.average_price,
                                  previous.status, previous.exec_type, False, "Unknown or non-resting order", frames)
        own = self._bids[resting.symbol] if resting.side == "BUY" else self._asks[resting.symbol]
        queue = own[resting.limit_price]
        own[resting.limit_price] = deque(item for item in queue if item.cl_ord_id != cl_ord_id)
        if not own[resting.limit_price]:
            del own[resting.limit_price]
        average = previous.average_price
        frames.append(self._report(cl_ord_id, previous.symbol, previous.side, previous.order_qty,
                                   previous.limit_price, previous.cum_qty, Decimal(0), average,
                                   status="4", exec_type="4", order_id=f"EX-{cl_ord_id}"))
        result = MatchingResult(previous.cl_ord_id, previous.symbol, previous.side, previous.order_qty,
                                previous.limit_price, previous.cum_qty, Decimal(0), average,
                                "4", "4", False, None, frames)
        self._order_states[cl_ord_id] = result
        return result

    def replace_order(
        self,
        cl_ord_id: str,
        *,
        new_quantity: Decimal | str | int,
        new_limit_price: Decimal | str,
    ) -> MatchingResult:
        """Replace a live order; successful replace loses its old queue priority."""
        previous = self._order_states.get(cl_ord_id)
        if previous is None or previous.leaves_qty <= 0:
            raise KeyError(f"No live leaves remain for ClOrdID {cl_ord_id!r}")
        self._remove_resting(cl_ord_id)
        return self.match_new_order(previous.symbol, previous.side, new_quantity, new_limit_price,
                                    orig_cl_ord_id=cl_ord_id)

    def _remove_resting(self, cl_ord_id: str) -> None:
        resting = self._orders.pop(cl_ord_id, None)
        if resting is None:
            return
        own = self._bids[resting.symbol] if resting.side == "BUY" else self._asks[resting.symbol]
        queue = own.get(resting.limit_price)
        if queue is not None:
            own[resting.limit_price] = deque(item for item in queue if item.cl_ord_id != cl_ord_id)
            if not own[resting.limit_price]:
                del own[resting.limit_price]

    def get_book_snapshot(self, symbol: str) -> dict[str, Any]:
        """Return decimal-string depth, spread, mid and last-trade values."""
        symbol = symbol.upper()
        if symbol not in self.MARKET:
            raise ValueError(f"Unsupported symbol {symbol!r}")
        bids = self._bids[symbol]
        asks = self._asks[symbol]
        bid_levels = [
            {"price": str(price), "quantity": str(sum((order.leaves_qty for order in queue), Decimal(0)))}
            for price, queue in sorted(bids.items(), reverse=True) if queue
        ][:5]
        ask_levels = [
            {"price": str(price), "quantity": str(sum((order.leaves_qty for order in queue), Decimal(0)))}
            for price, queue in sorted(asks.items()) if queue
        ][:5]
        best_bid = Decimal(bid_levels[0]["price"]) if bid_levels else None
        best_ask = Decimal(ask_levels[0]["price"]) if ask_levels else None
        return {
            "symbol": symbol,
            "bids": bid_levels,
            "asks": ask_levels,
            "best_bid": str(best_bid) if best_bid is not None else None,
            "best_ask": str(best_ask) if best_ask is not None else None,
            "spread": str(best_ask - best_bid) if best_ask is not None and best_bid is not None else None,
            "mid_price": str((best_ask + best_bid) / Decimal(2)) if best_ask is not None and best_bid is not None else str(self.MARKET[symbol][0]),
            "last_trade_price": str(self._last_trade[symbol]) if self._last_trade[symbol] is not None else None,
        }

    def get_all_snapshots(self) -> list[dict[str, Any]]:
        return [self.get_book_snapshot(symbol) for symbol in self.MARKET]

    def get_order(self, cl_ord_id: str) -> MatchingResult | None:
        return self._order_states.get(cl_ord_id)
