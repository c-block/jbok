package jbok.core

import jbok.core.models._
import scodec.bits._

object Fixtures {

  object Blocks {

    trait FixtureBlock {
      val header: BlockHeader
      val body: BlockBody
      val transactionHashes: List[ByteVector]
      val size: Long

      def block: Block = Block(header, body)
    }

    object ValidBlock extends FixtureBlock {
      // Arbitrary taken Block 3125369
      override val header: BlockHeader                 = Block3125369.header
      override val body: BlockBody                     = Block3125369.body
      override val transactionHashes: List[ByteVector] = Block3125369.transactionHashes
      override val size: Long                          = Block3125369.size
    }

    private val chainId: Byte = 0x3d.toByte

    object Block3125369 extends FixtureBlock {
      val header = BlockHeader(
        parentHash = hex"8345d132564b3660aa5f27c9415310634b50dbc92579c65a0825d9a255227a71",
        ommersHash = hex"1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        beneficiary = hex"df7d7e053933b5cc24372f878c90e62dadad5d42",
        stateRoot = hex"087f96537eba43885ab563227262580b27fc5e6516db79a6fc4d3bcd241dda67",
        transactionsRoot = hex"8ae451039a8bf403b899dcd23252d94761ddd23b88c769d9b7996546edc47fac",
        receiptsRoot = hex"8b472d8d4d39bae6a5570c2a42276ed2d6a56ac51a1a356d5b17c5564d01fd5d",
        logsBloom = ByteVector.fromValidHex("0" * 512),
        difficulty = BigInt("14005986920576"),
        number = 3125369,
        gasLimit = 4699996,
        gasUsed = 84000,
        unixTimestamp = 1486131165,
        extraData = hex"d5830104098650617269747986312e31332e30826c69",
        mixHash = hex"be90ac33b3f6d0316e60eef505ff5ec7333c9f3c85c1a36fc2523cd6b75ddb8a",
        nonce = hex"2b0fb0c002946392"
      )

      val body = BlockBody(
        transactionList = List[SignedTransaction](
          SignedTransaction(
            tx = Transaction(
              nonce = BigInt("438550"),
              gasPrice = BigInt("20000000000"),
              gasLimit = BigInt("50000"),
              receivingAddress = Address(hex"ee4439beb5c71513b080bbf9393441697a29f478"),
              value = BigInt("1265230129703017984"),
              payload = ByteVector.empty
            ),
            chainId,
            0x9d.toByte,
            hex"5b496e526a65eac3c4312e683361bfdb873741acd3714c3bf1bcd7f01dd57ccb",
            hex"3a30af5f529c7fc1d43cfed773275290475337c5e499f383afd012edcc8d7299"
          ),
          SignedTransaction(
            tx = Transaction(
              nonce = BigInt("438551"),
              gasPrice = BigInt("20000000000"),
              gasLimit = BigInt("50000"),
              receivingAddress = Address(hex"c68e9954c7422f479e344faace70c692217ea05b"),
              value = BigInt("656010196207162880"),
              payload = ByteVector.empty
            ),
            chainId,
            0x9d.toByte,
            hex"377e542cd9cd0a4414752a18d0862a5d6ced24ee6dba26b583cd85bc435b0ccf",
            hex"579fee4fd96ecf9a92ec450be3c9a139a687aa3c72c7e43cfac8c1feaf65c4ac"
          ),
          SignedTransaction(
            tx = Transaction(
              nonce = BigInt("438552"),
              gasPrice = BigInt("20000000000"),
              gasLimit = BigInt("50000"),
              receivingAddress = Address(hex"19c5a95eeae4446c5d24363eab4355157e4f828b"),
              value = BigInt("3725976610361427456"),
              payload = ByteVector.empty
            ),
            chainId,
            0x9d.toByte,
            hex"a70267341ba0b33f7e6f122080aa767d52ba4879776b793c35efec31dc70778d",
            hex"3f66ed7f0197627cbedfe80fd8e525e8bc6c5519aae7955e7493591dcdf1d6d2"
          ),
          SignedTransaction(
            tx = Transaction(
              nonce = BigInt("438553"),
              gasPrice = BigInt("20000000000"),
              gasLimit = BigInt("50000"),
              receivingAddress = Address(hex"3435be928d783b7c48a2c3109cba0d97d680747a"),
              value = BigInt("108516826677274384"),
              payload = ByteVector.empty
            ),
            chainId,
            0x9d.toByte,
            hex"beb8226bdb90216ca29967871a6663b56bdd7b86cf3788796b52fd1ea3606698",
            hex"2446994156bc1780cb5806e730b171b38307d5de5b9b0d9ad1f9de82e00316b5",
          )
        ),
        ommerList = List[BlockHeader]()
      )

      val transactionHashes = List(
        hex"af854c57c64191827d1c80fc50f716f824508973e12e4d4c60d270520ce72edb",
        hex"f3e33ba2cb400221476fa4025afd95a13907734c38a4a8dff4b7d860ee5adc8f",
        hex"202359a4c0b0f11ca07d44fdeb3502ffe91c86ad4a9af47c27f11b23653339f2",
        hex"067bd4b1a9d37ff932473212856262d59f999935a4a357faf71b1d7e276b762b"
      )

      val size = 1000L
    }

    object Genesis extends FixtureBlock {
      val header = BlockHeader(
        parentHash = hex"0000000000000000000000000000000000000000000000000000000000000000",
        ommersHash = hex"1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        beneficiary = hex"0000000000000000000000000000000000000000",
        stateRoot = hex"d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544",
        transactionsRoot = hex"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        receiptsRoot = hex"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        logsBloom = ByteVector.fromValidHex("0" * 512),
        difficulty = BigInt("17179869184"),
        number = 0,
        gasLimit = 5000,
        gasUsed = 0,
        unixTimestamp = 0,
        extraData = hex"11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa",
        mixHash = hex"0000000000000000000000000000000000000000000000000000000000000000",
        nonce = hex"0000000000000042"
      )
      override val body: BlockBody = BlockBody(
        transactionList = List[SignedTransaction](),
        ommerList = List[BlockHeader]()
      )
      override val transactionHashes: List[ByteVector] = List()
      override val size: Long                          = 540
    }

    object DaoForkBlock extends FixtureBlock {
      override val header: BlockHeader = BlockHeader(
        parentHash = hex"a218e2c611f21232d857e3c8cecdcdf1f65f25a4477f98f6f47e4063807f2308",
        ommersHash = hex"1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        beneficiary = hex"61c808d82a3ac53231750dadc13c777b59310bd9",
        stateRoot = hex"614d7d358b03cbdaf0343529673be20ad45809d02487f023e047efdce9da8aff",
        transactionsRoot = hex"d33068a7f21bff5018a00ca08a3566a06be4196dfe9e39f96e431565a619d455",
        receiptsRoot = hex"7bda9aa65977800376129148cbfe89d35a016dd51c95d6e6dc1e76307d315468",
        logsBloom = ByteVector.fromValidHex("0" * 512),
        difficulty = BigInt("62413376722602"),
        number = 1920000,
        gasLimit = 4712384,
        gasUsed = 84000,
        unixTimestamp = 1469020839,
        extraData = hex"e4b883e5bda9e7a59ee4bb99e9b1bc",
        mixHash = hex"c52daa7054babe515b17ee98540c0889cf5e1595c5dd77496997ca84a68c8da1",
        nonce = hex"05276a600980199d"
      )
      override val body: BlockBody = BlockBody(
        transactionList = List[SignedTransaction](
          SignedTransaction(
            tx = Transaction(
              nonce = BigInt("1"),
              gasPrice = BigInt("20000000000"),
              gasLimit = BigInt("21000"),
              receivingAddress = Address(hex"53d284357ec70ce289d6d64134dfac8e511c8a3d"),
              value = BigInt("10046680000000000000"),
              payload = ByteVector.empty
            ),
            chainId,
            0x1b.toByte,
            hex"8d94a55c7ac7adbfa2285ef7f4b0c955ae1a02647452cd4ead03ee6f449675c6",
            hex"67149821b74208176d78fc4dffbe37c8b64eecfd47532406b9727c4ae8eb7c9a",
          ),
          SignedTransaction(
            tx = Transaction(
              nonce = BigInt("1"),
              gasPrice = BigInt("20000000000"),
              gasLimit = BigInt("21000"),
              receivingAddress = Address(hex"53d284357ec70ce289d6d64134dfac8e511c8a3d"),
              value = BigInt("20093780000000000000"),
              payload = ByteVector.empty
            ),
            chainId,
            0x1c.toByte,
            hex"6d31e3d59bfea97a34103d8ce767a8fe7a79b8e2f30af1e918df53f9e78e69ab",
            hex"098e5b80e1cc436421aa54eb17e96b08fe80d28a2fbd46451b56f2bca7a321e7",
          ),
          SignedTransaction(
            tx = Transaction(
              nonce = BigInt("1"),
              gasPrice = BigInt("20000000000"),
              gasLimit = BigInt("21000"),
              receivingAddress = Address(hex"53d284357ec70ce289d6d64134dfac8e511c8a3d"),
              value = BigInt("1502561962583879700"),
              payload = ByteVector.empty
            ),
            chainId,
            0x1b.toByte,
            hex"fdbbc462a8a60ac3d8b13ee236b45af9b7991cf4f0f556d3af46aa5aeca242ab",
            hex"5de5dc03fdcb6cf6d14609dbe6f5ba4300b8ff917c7d190325d9ea2144a7a2fb",
          ),
          SignedTransaction(
            tx = Transaction(
              nonce = BigInt("1"),
              gasPrice = BigInt("20000000000"),
              gasLimit = BigInt("21000"),
              receivingAddress = Address(hex"53d284357ec70ce289d6d64134dfac8e511c8a3d"),
              value = BigInt("1022338440000000000"),
              payload = ByteVector.empty
            ),
            chainId,
            0x1b.toByte,
            hex"bafb9f71cef873b9e0395b9ed89aac4f2a752e2a4b88ba3c9b6c1fea254eae73",
            hex"1cef688f6718932f7705d9c1f0dd5a8aad9ddb196b826775f6e5703fdb997706",
          )
        ),
        ommerList = List[BlockHeader]()
      )

      override val transactionHashes: List[ByteVector] = List(
        hex"6f75b64d9364b71b43cde81a889f95df72e6be004b28477f9083ed0ee471a7f9",
        hex"50d8156ee48d01b56cb17b6cb2ac8f29e1bf565be0e604b2d8ffb2fb50a0f611",
        hex"4677a93807b73a0875d3a292eacb450d0af0d6f0eec6f283f8ad927ec539a17b",
        hex"2a5177e6d6cea40594c7d4b0115dcd087443be3ec2fa81db3c21946a5e51cea9"
      )
      override val size: Long = 978L
    }

    object ProDaoForkBlock extends FixtureBlock {
      override val header: BlockHeader = BlockHeader(
        parentHash = hex"a218e2c611f21232d857e3c8cecdcdf1f65f25a4477f98f6f47e4063807f2308",
        ommersHash = hex"1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        beneficiary = hex"bcdfc35b86bedf72f0cda046a3c16829a2ef41d1 ",
        stateRoot = hex"c5e389416116e3696cce82ec4533cce33efccb24ce245ae9546a4b8f0d5e9a75",
        transactionsRoot = hex"7701df8e07169452554d14aadd7bfa256d4a1d0355c1d174ab373e3e2d0a3743",
        receiptsRoot = hex"26cf9d9422e9dd95aedc7914db690b92bab6902f5221d62694a2fa5d065f534b",
        logsBloom = ByteVector.fromValidHex("0" * 512),
        difficulty = BigInt("62413376722602"),
        number = 1920000,
        gasLimit = 4712384,
        gasUsed = 84000,
        unixTimestamp = 1469020840,
        extraData = hex"64616f2d686172642d666f726b",
        mixHash = hex"5b5acbf4bf305f948bd7be176047b20623e1417f75597341a059729165b92397",
        nonce = hex"bede87201de42426"
      )
      override lazy val body: BlockBody = BlockBody(
        transactionList = List[SignedTransaction](
          SignedTransaction(
            tx = Transaction(
              nonce = BigInt("1"),
              gasPrice = BigInt("20000000000"),
              gasLimit = BigInt("21000"),
              receivingAddress = Address(hex"53d284357ec70ce289d6d64134dfac8e511c8a3d"),
              value = BigInt("1502561962583879700"),
              payload = ByteVector.empty
            ),
            0x3d.toByte,
            0x1b.toByte,
            hex"fdbbc462a8a60ac3d8b13ee236b45af9b7991cf4f0f556d3af46aa5aeca242ab",
            hex"5de5dc03fdcb6cf6d14609dbe6f5ba4300b8ff917c7d190325d9ea2144a7a2fb",
          ),
          SignedTransaction(
            tx = Transaction(
              nonce = BigInt("1"),
              gasPrice = BigInt("20000000000"),
              gasLimit = BigInt("21000"),
              receivingAddress = Address(hex"53d284357ec70ce289d6d64134dfac8e511c8a3d"),
              value = BigInt("10046680000000000000"),
              payload = ByteVector.empty
            ),
            chainId,
            0x1b.toByte,
            hex"8d94a55c7ac7adbfa2285ef7f4b0c955ae1a02647452cd4ead03ee6f449675c6",
            hex"67149821b74208176d78fc4dffbe37c8b64eecfd47532406b9727c4ae8eb7c9a",
          ),
          SignedTransaction(
            tx = Transaction(
              nonce = BigInt("1"),
              gasPrice = BigInt("20000000000"),
              gasLimit = BigInt("21000"),
              receivingAddress = Address(hex"53d284357ec70ce289d6d64134dfac8e511c8a3d"),
              value = BigInt("20093780000000000000"),
              payload = ByteVector.empty
            ),
            chainId,
            0x1c.toByte,
            hex"6d31e3d59bfea97a34103d8ce767a8fe7a79b8e2f30af1e918df53f9e78e69ab",
            hex"098e5b80e1cc436421aa54eb17e96b08fe80d28a2fbd46451b56f2bca7a321e7",
          ),
          SignedTransaction(
            tx = Transaction(
              nonce = BigInt("1"),
              gasPrice = BigInt("20000000000"),
              gasLimit = BigInt("21000"),
              receivingAddress = Address(hex"53d284357ec70ce289d6d64134dfac8e511c8a3d"),
              value = BigInt("1022338440000000000"),
              payload = ByteVector.empty
            ),
            chainId,
            0x1b.toByte,
            hex"bafb9f71cef873b9e0395b9ed89aac4f2a752e2a4b88ba3c9b6c1fea254eae73",
            hex"1cef688f6718932f7705d9c1f0dd5a8aad9ddb196b826775f6e5703fdb997706",
          )
        ),
        ommerList = List[BlockHeader]()
      )

      override val transactionHashes: List[ByteVector] = List(
        hex"4677a93807b73a0875d3a292eacb450d0af0d6f0eec6f283f8ad927ec539a17b",
        hex"6f75b64d9364b71b43cde81a889f95df72e6be004b28477f9083ed0ee471a7f9",
        hex"50d8156ee48d01b56cb17b6cb2ac8f29e1bf565be0e604b2d8ffb2fb50a0f611",
        hex"2a5177e6d6cea40594c7d4b0115dcd087443be3ec2fa81db3c21946a5e51cea9"
      )
      override val size: Long = 976
    }

    object DaoParentBlock extends FixtureBlock {
      override val header: BlockHeader = BlockHeader(
        parentHash = hex"505ffd21f4cbf2c5c34fa84cd8c92525f3a719b7ad18852bffddad601035f5f4",
        ommersHash = hex"1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        beneficiary = hex"2a65aca4d5fc5b5c859090a6c34d164135398226",
        stateRoot = hex"fdf2fc04580b95ca15defc639080b902e93892dcce288be0c1f7a7bbc778248b",
        transactionsRoot = hex"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        receiptsRoot = hex"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        logsBloom = ByteVector.fromValidHex("00" * 256),
        difficulty = BigInt("62382916183238"),
        number = 1919999,
        gasLimit = 4707788,
        gasUsed = 0,
        unixTimestamp = 1469020838,
        extraData = hex"4477617266506f6f6c",
        mixHash = hex"7f9ac1ddeafff0f926ed9887b8cf7d50c3f919d902e618b957022c46c8b404a6",
        nonce = hex"60832709c8979daa"
      )
      override lazy val body: BlockBody                     = ???
      override lazy val transactionHashes: List[ByteVector] = ???
      override lazy val size: Long                          = ???
    }
  }
}
