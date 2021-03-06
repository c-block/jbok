package jbok.app.views

import cats.effect.IO
import cats.implicits._
import com.thoughtworks.binding
import com.thoughtworks.binding.Binding
import com.thoughtworks.binding.Binding.{Constants, Var, Vars}
import jbok.app.{AppState, Contract}
import jbok.core.models.{Account, Address}
import org.scalajs.dom.raw._
import org.scalajs.dom.{Element, _}
import org.scalajs.dom
import scodec.bits.ByteVector
import io.circe.parser._
import jbok.app.components.{AddressOptionInput, Input, Notification}
import jbok.app.helper.InputValidator
import jbok.common.math.N
import jbok.core.api.{BlockTag, CallTx}
import jbok.evm.solidity.ABIDescription.FunctionDescription
import jbok.app.execution._

@SuppressWarnings(Array("org.wartremover.warts.OptionPartial", "org.wartremover.warts.EitherProjectionPartial"))
final case class CallTxView(state: AppState) {
  val nodeAccounts = Vars.empty[Address]
  val contracts    = Vars.empty[Address]

  val currentId                                           = state.activeNode.value
  val client                                              = currentId.flatMap(state.clients.value.get(_))
  val lock: Var[Boolean]                                  = Var(false)
  val account: Var[Option[Account]]                       = Var(None)
  val to: Var[String]                                     = Var("")
  val toSyntax: Var[Boolean]                              = Var(true)
  val passphrase: Var[String]                             = Var("")
  val rawResult: Var[ByteVector]                          = Var(ByteVector.empty)
  val result: Var[String]                                 = Var("")
  val contractAbi: Var[Option[List[FunctionDescription]]] = Var(None)
  val contractSelected: Var[Boolean]                      = Var(false)
  val function: Var[Option[FunctionDescription]]          = Var(None)
  val txType: Var[String]                                 = Var("Send")
  val statusMessage: Var[Option[String]]                  = Var(None)

  val paramInputs: Vars[Input] = Vars.empty[Input]

  private def fetch() = {
    val p = for {
      accounts <- client.traverse(_.personal.listAccounts)
      _ = accounts.map(nodeAccounts.value ++= _)
    } yield ()
    p.unsafeToFuture()
  }

  fetch()

  private def reset(): Unit = {
    rawResult.value = ByteVector.empty
    result.value = ""

    val element = dom.document.getElementById("decodeSelect")
    element match {
      case x: HTMLSelectElement =>
        x.value = "decode"
      case _ => ()
    }
  }

  private val toOnChange = { event: Event =>
    event.currentTarget match {
      case select: HTMLSelectElement =>
        val v = select.options(select.selectedIndex).value
        if (v == "default") {
          contractSelected.value = false
          contractAbi.value = None
        } else {
          to.value = v.substring(2)
          toSyntax.value = InputValidator.isValidAddress(to.value)
          contractSelected.value = true
          contractAbi.value = state.nodes.value
            .get(state.activeNode.value.getOrElse(""))
            .flatMap {
              _.contractsABI.value.get(Address.fromHex(v))
            }
            .map(_.abi)
        }
        function.value = None
        paramInputs.value.clear()
      case _ =>
    }
  }

  private val functionOnChange = { event: Event =>
    event.currentTarget match {
      case select: HTMLSelectElement =>
        val v = select.options(select.selectedIndex).value
        if (v == "default") {
          function.value = None
        } else {
          function.value = contractAbi.value.flatMap(_.find(_.name.contains(v)))
          function.value.foreach { f =>
            if (f.stateMutability == "view")
              txType.value = "Call"
            else
              txType.value = "Send"
          }
          function.value.map { f =>
            val t = f.inputs.map { p =>
              val validator = InputValidator
                .getValidator(p.parameterType)
                .getOrElse((value: String) => {
                  val json = parse(s"[${value}]")
                  json.isRight
                })
              val (prefix, suffix) = InputValidator.getInputPrefixAndSuffix(p.parameterType)
              Input(p.name.getOrElse(""), p.parameterType.typeString, validator = validator, prefix = prefix, suffix = suffix)
            }
            paramInputs.value.clear()
            paramInputs.value ++= t
          }
        }
        reset()
      case _ =>
    }
  }

  private val passphraseOnInput = { event: Event =>
    event.currentTarget match {
      case input: HTMLInputElement => passphrase.value = input.value.trim
      case _                       =>
    }
  }

  private def decodeByteVector(d: String): String = d match {
    case "decode" => {
      function.value
        .map { f =>
          val result = f.decode(rawResult.value)
          val prompt = f.outputs.map(_.parameterType.typeString).mkString("[", ",", "]")
          result.fold(e => e.toString, v => s"${prompt}: ${v.noSpaces}")
        }
        .getOrElse("")
    }
    case _ => rawResult.value.toHex
  }

  private val onChangeHandlerDecode = { event: Event =>
    event.currentTarget match {
      case select: HTMLSelectElement =>
        val v = select.options(select.selectedIndex).value
        result.value = decodeByteVector(v)
    }
  }

  def checkAndGenerateInput() = {
    statusMessage.value = None
    for {
      _       <- if (!lock.value) Right(()) else Left("please wait for last tx.")
      from    <- if (addressOptionInput.isValid) Right(addressOptionInput.value) else Left("not valid from address.")
      to      <- if (toSyntax.value) Right(to.value) else Left("not valid to address.")
      _       <- if (paramInputs.value.toList.forall(_.isValid)) Right(()) else Left("no valid params input.")
      _       <- if (client.nonEmpty) Right(()) else Left("no connect client.")
      abiFunc <- Either.fromOption(function.value, "error contract abi function.")
      _ = println(paramInputs.value.toList.map(_.value).mkString("[", ",", "]"))
      data <- if (abiFunc.inputs.isEmpty) {
        Right(abiFunc.methodID)
      } else {
        abiFunc.encode(paramInputs.value.toList.map(_.value).mkString("[", ",", "]")).leftMap(e => e.toString)
      }
    } yield execute(from, to, data)
  }

  def execute(from: String, to: String, data: ByteVector) = {
    lock.value = true
    reset()
    val fromSubmit = Address(ByteVector.fromValidHex(from))
    val toSubmit   = Some(Address(ByteVector.fromValidHex(to)))
    val callTx     = CallTx(Some(fromSubmit), toSubmit, None, N(1), N(0), data)
    val p = if (txType.value == "Call") {
      for {
        ret <- client.get.contract.call(callTx, BlockTag.latest)
        _ = rawResult.value = ret
        _ = result.value = decodeByteVector("decode")
        _ = statusMessage.value = Some("call success")
        _ = lock.value = false
      } yield ()
    } else {
      val password = if (passphrase.value.isEmpty) "" else passphrase.value
      for {
        account  <- client.get.account.getAccount(fromSubmit, BlockTag.latest)
        gasLimit <- client.get.contract.getEstimatedGas(callTx, BlockTag.latest)
        gasPrice <- client.get.contract.getGasPrice
        _ = statusMessage.value = Some(s"gas limit: $gasLimit, gas price: $gasPrice")
        txHash <- client.get.personal
          .sendTransaction(fromSubmit, password, toSubmit, None, Some(gasLimit), Some(gasPrice), Some(account.nonce), Some(data))
        stx <- client.get.transaction.getTx(txHash)
        _ = stx.foreach(state.addStx(currentId.get, _))
        _ = statusMessage.value = Some(s"send transaction success: ${txHash.toHex}")
        _ = lock.value = false
      } yield ()
    }

    p.timeout(state.config.value.clientTimeout)
      .handleErrorWith(e => IO.delay(lock.value = false) >> IO.delay(statusMessage.value = Some(s"deploy failed: ${e}")))
      .unsafeToFuture()
  }

  val executeOnClick = (_: Event) => checkAndGenerateInput().leftMap(error => statusMessage.value = Some(error))

  val addressOptionInput = AddressOptionInput(nodeAccounts)

  @binding.dom
  def render: Binding[Element] =
    <div>
      <div>
        {addressOptionInput.render.bind}
      </div>
      <div>
        <label for="to">
          <b>
            to
          </b>
        </label>
        <select name="to" class="autocomplete" onchange={toOnChange}>
          {
            val contractList = state.nodes.value.get(currentId.getOrElse("")).map(_.contractsABI).getOrElse(Var(Map.empty[Address, Contract])).bind
            for (account <- Constants(contractList.keys.toList: _*)) yield {
              <option value={account.toString}>{account.toString}</option>
            }
          }
          <option value="default" disabled={true} selected={true}>Pick A Contract</option>
        </select>
      </div>

      {
        if(contractSelected.bind) {
          <div>
            <label for="functionSelect">
              <b>
                function
              </b>
            </label>
            {
              contractAbi.bind match {
                case None =>
                  <div/>
                case Some(functions) =>
                  <div>
                    <select name="functionSelect" class="autocomplete" onchange={functionOnChange}>
                      {
                        for (vf <- Constants(functions.filter(_.name != "constructor"): _*)) yield {
                          val fn = vf.name
                          <option value={fn}>{fn}</option>
                        }
                      }
                      <option value="default" disabled={true} selected={true}>Pick A Function</option>
                    </select>
                  </div>
              }
            }
            {
              for (param <- Constants(paramInputs.all.bind.toList: _*)) yield {
                <div>
                  <label for={param.name}>
                    <b>{param.name.stripPrefix("_")}</b>
                  </label>
                  {param.render.bind}
                </div>
              }
            }
          </div>
        } else {
          <div/>
        }
      }

      {
        if (txType.bind == "Call") {
          <div>
            <label for="result">
              <b>
                result
              </b>
            </label>
            <select id="decodeSelect" class="autocomplete" onchange={onChangeHandlerDecode}>
              <option value="decode">decode</option>
              <option value="default">raw</option>
            </select>
            <input type="text" placeholder="Click Call to Get Result" name="result" value={result.bind} class="valid" disabled={true}/>
          </div>
        } else {
          <div>
            <label for="passphase">
              <b>
                passphase
              </b>
            </label>
            <input type="password" name="passphase" oninput={passphraseOnInput} value={passphrase.bind}/>
          </div>
        }
      }

      {
        val onclose = (_: Event) => statusMessage.value = None
        @binding.dom def content(status: String):Binding[Element] =
          <div style="padding-left: 10px">{status}</div>
        statusMessage.bind match {
          case None => <div/>
          case Some(status) if status.contains("success") => Notification.renderSuccess(content(status), onclose).bind
          case Some(status) => Notification.renderWarning(content(status), onclose).bind
        }
      }


      <div>
        <button id="call" class="modal-confirm" style={"width: 100%"} onclick={executeOnClick} disabled={state.activeNode.bind.isEmpty || function.bind.isEmpty}>{txType.bind}</button>
      </div>
    </div>
}
