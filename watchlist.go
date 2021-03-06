package eth

var monitoredAddressesMap = make(map[string]bool)

func InitAddressMap() {
	// rinkeby test
	// monitoredAddressesMap["0xffe7642922f0f6010291acd934bb18f174aaa218"] = false
	// mainnet prod
	monitoredAddressesMap["0x00d3095bb5fb5deba1a0b38ab0233805150f3f61"] = false
	monitoredAddressesMap["0x01da76b7d1ec4ba99e27f8e4acdb15b79f5eebea"] = false
	monitoredAddressesMap["0x028990d32a8e48110ea88be2bdb2fe5369c150b9"] = false
	monitoredAddressesMap["0x02f66a7d5657ee67be39349988aa1f944206ead3"] = false
	monitoredAddressesMap["0x033226720ff886982508c9704960118a72466fa9"] = false
	monitoredAddressesMap["0x0470ccbd8ea7d2c233dff3ffef012984de883e98"] = false
	monitoredAddressesMap["0x04b606a6168f3bbb06dd1e7cfe9b4fe595d8a7d7"] = false
	monitoredAddressesMap["0x06db439df1ce981c063812d226a4dd540fab99cb"] = false
	monitoredAddressesMap["0x09385fd889d4e5bab449b5983e237bded4c22167"] = false
	monitoredAddressesMap["0x0b6f3985871a9da9f02ef9208f71bbad7471b087"] = false
	monitoredAddressesMap["0x0c06a951bb84fbcaff105529971af83b680c0dd1"] = false
	monitoredAddressesMap["0x0cd2795a623adeb9370e2895e8d7526a6e4c556d"] = false
	monitoredAddressesMap["0x0ed5e1f8e5ae8b3f2e22b89be67178c4f8fed2e6"] = false
	monitoredAddressesMap["0x0effb1825953479fc01224cce28fea02bd9a211d"] = false
	monitoredAddressesMap["0x0af0da6c41a5e53d5b6464750f638af7561d95f0"] = false
	monitoredAddressesMap["0x0c8a9ea8a3844253eceb6a0301d7901119a6da8d"] = false
	monitoredAddressesMap["0x11c9e9d921c30d8441131d543df2db72a9c7b2b2"] = false
	monitoredAddressesMap["0x12cf6cb8cbe3f958682a5ebe05f2f5e4c52f804d"] = false
	monitoredAddressesMap["0x13c8a8ea68b8b54bb271d1c4177be2a0d0edf220"] = false
	monitoredAddressesMap["0x13dc9ceb6598db3c2ffb9ea9e94569893ee1e1db"] = false
	monitoredAddressesMap["0x14b0743f603ef2104bfd01c30f8f98d9d3310470"] = false
	monitoredAddressesMap["0x150a2704f761bfe5aba3fd57892258acaf3d2860"] = false
	monitoredAddressesMap["0x162caf2d552806a404aba22f5d3aa06457bd4923"] = false
	monitoredAddressesMap["0x16466faa872e7ab4815da0ebdf12d7b188872a60"] = false
	monitoredAddressesMap["0x16723234c2f30bea552bf938142bf56a1b1966ac"] = false
	monitoredAddressesMap["0x17203e2784bab9f40cf6b805f4bd0b0b95777218"] = false
	monitoredAddressesMap["0x17235f077f0d004e91f5a9196737895edd246b2c"] = false
	monitoredAddressesMap["0x17455b6ce4cdf9054e3b3bd6cf7658dac56b3043"] = false
	monitoredAddressesMap["0x18d10e679f48a9b19ebf9f80093ef141f3a12b81"] = false
	monitoredAddressesMap["0x1a3885c9404e5ecff0bccbf571292b237156389b"] = false
	monitoredAddressesMap["0x1be71e871294156b43e52ffe77deeddb9ab994eb"] = false
	monitoredAddressesMap["0x1d5321e125f6c7079a716705541c7b371ca79e69"] = false
	monitoredAddressesMap["0x1ff2a53dd11d24fb5161632939d77cd7676ca1ec"] = false
	monitoredAddressesMap["0x1a375d0880ccefae658d6351a9a700d5ff496c92"] = false
	monitoredAddressesMap["0x1c764a70797deb7100037581e679684cc5c9ca42"] = false
	monitoredAddressesMap["0x1d8a5212ae7c196cafbf58ad5f75b7ac9bdeb0b9"] = false
	monitoredAddressesMap["0x20cbcaa2efe89d85c402da26369a90fb8beda471"] = false
	monitoredAddressesMap["0x213b57ac2cbbf92ffd13b580838879fcb29f35b9"] = false
	monitoredAddressesMap["0x215f4d5ae68b80df77e827af4ee334f3ce459733"] = false
	monitoredAddressesMap["0x21d7e78fd9b56b274cda096a8f3dbc3f02ecc312"] = false
	monitoredAddressesMap["0x253e497fbd3d0397d3cb78d20d0d8ba74dd19480"] = false
	monitoredAddressesMap["0x25975e7ac29347ac5a248e29d681b871f2ce437f"] = false
	monitoredAddressesMap["0x25ce833289ef3a1464e82d4dbe4223aff739259b"] = false
	monitoredAddressesMap["0x26affb7f84b9985c4cf53b03f51098210af279a1"] = false
	monitoredAddressesMap["0x273a5d3e6721b9f5c1a6474f560c1334c63dda01"] = false
	monitoredAddressesMap["0x2755d1e38bc41aa42ca9bbef7cbde67944bf2173"] = false
	monitoredAddressesMap["0x2a9f4b1510ca802bf99aa3bad2a8065313471640"] = false
	monitoredAddressesMap["0x2bbf66aa46d62c7216f17e8dfc836feca7becb87"] = false
	monitoredAddressesMap["0x2cb3f1de33b0fe6c9f02d85c4c16db69cb243c83"] = false
	monitoredAddressesMap["0x2d17698b21663a928242412c2734a8fc536f95e6"] = false
	monitoredAddressesMap["0x2c6512deaaacf0c27470b91c1781859c0c46a20f"] = false
	monitoredAddressesMap["0x2f4ecdae84f234ef7ce4e0c24604e8fe0bfdb9b8"] = false
	monitoredAddressesMap["0x300780ac51b03751736ff15c9e805996f0dc64f1"] = false
	monitoredAddressesMap["0x30bc40ddbd9a466b88dc0ba6a1c014d3d26caaf7"] = false
	monitoredAddressesMap["0x31cd68b798d390dd4ad84da4d01a9c1f58fde3b9"] = false
	monitoredAddressesMap["0x33516d47ce28afd27e786613b67e3341c846220e"] = false
	monitoredAddressesMap["0x34006681faae8e2cb3de5f92a4304c011dda3e3b"] = false
	monitoredAddressesMap["0x34ef8b7d2ec51a62cfba2ac9f11f9fed29fa3fed"] = false
	monitoredAddressesMap["0x351c11a5c538b53404cf952a3ed544a86e8af28b"] = false
	monitoredAddressesMap["0x3617dab70df912856829c08a54f6a7aadd5d1a43"] = false
	monitoredAddressesMap["0x3622bada99b27dbfe535853e5741364eec6e1301"] = false
	monitoredAddressesMap["0x36309a61594f804fc9d3babbb4bec064911ee06f"] = false
	monitoredAddressesMap["0x363c45a9c4650e73ffc79f1e09cbab07adf33c7f"] = false
	monitoredAddressesMap["0x36f74da7d812a10356fd69a120ee138c53ce7a77"] = false
	monitoredAddressesMap["0x387687c0546da077576d2f308bbe805c8d378b5c"] = false
	monitoredAddressesMap["0x39c968c2984b750fb0db989782638b8a56cc9cbc"] = false
	monitoredAddressesMap["0x39dc3f7adc8cad2b03c831c7771a25d4fb99021e"] = false
	monitoredAddressesMap["0x3b2ceb8a5411aa1ab60d3d8eb450d9fa39a41176"] = false
	monitoredAddressesMap["0x3f7070f10257bfd19b92032940362be0731fa43a"] = false
	monitoredAddressesMap["0x3fc04e4063bea08c66574e5bcfd5c8193b0eb401"] = false
	monitoredAddressesMap["0x3b39f6e82cf73e4bd4c87cb50c8f6850906987a6"] = false
	monitoredAddressesMap["0x3c4c9b867d2fc758c5562d70dcf3bda94fb13f4e"] = false
	monitoredAddressesMap["0x3c6e9be59d3b071d17a32790624c3e42b7c464c7"] = false
	monitoredAddressesMap["0x3e0767ebb315460b02d438e9fa52111c85d74434"] = false
	monitoredAddressesMap["0x414bb2324e61349309e242a38b59948e17f8eaaa"] = false
	monitoredAddressesMap["0x418223d772d1f38438fb691bde3d630b6ae114a9"] = false
	monitoredAddressesMap["0x41a314f6b17e2cfefd3692be7453ed76bb783122"] = false
	monitoredAddressesMap["0x4203d1fc8cc0557615ce5592b0cee4ffba04e21b"] = false
	monitoredAddressesMap["0x422d7c1f2f04e7582163d1381a436516f4de3c2a"] = false
	monitoredAddressesMap["0x42a82aad780ed8654621e6ef2fb1f8ded9a33f55"] = false
	monitoredAddressesMap["0x435b9d077f4cf97e6e4b48f73dda354e0577b266"] = false
	monitoredAddressesMap["0x4406fa4e664352d256388a5fbcda800e40f17f75"] = false
	monitoredAddressesMap["0x4529d44f539feace353ecdabd985b61ce5d48408"] = false
	monitoredAddressesMap["0x45f8939b05227697b152d3c16a911b8906f589ca"] = false
	monitoredAddressesMap["0x4683ee96ed9c35fe564d2e8de4e47283b95fe280"] = false
	monitoredAddressesMap["0x468d01b3fe0b746430ab4ba3d652af70b913d122"] = false
	monitoredAddressesMap["0x477e17f7296e667ec54eecbb37b50b1dd8340808"] = false
	monitoredAddressesMap["0x483b43ad3ffac4d887daed5c1fa9dae7bce3bf73"] = false
	monitoredAddressesMap["0x4a57d0208164a1c1c63c75395dc444428a07b50a"] = false
	monitoredAddressesMap["0x4ac0f0b6c3b51b8377767a3d461b62b4444608e1"] = false
	monitoredAddressesMap["0x4b882992f3d4081c1f3a9336c4cc45db5675b42f"] = false
	monitoredAddressesMap["0x4de3df9e40de01adb4b33a4d750adbae867c25e2"] = false
	monitoredAddressesMap["0x508148ce48b695dc03ab8afc3d61909f51aa7fe5"] = false
	monitoredAddressesMap["0x509b3f7ef9e29953f929baa4893cfbac9ec805d3"] = false
	monitoredAddressesMap["0x51a941d3c8f5d761dba43a7621f8eebbcbe7dd3b"] = false
	monitoredAddressesMap["0x53165bfd03e5158157894a278e0a9640277ba66d"] = false
	monitoredAddressesMap["0x54bf2d4a393abc35beb10f4cf4663b3a27092268"] = false
	monitoredAddressesMap["0x567221f768451625a3fef8bf03ba03be52269f82"] = false
	monitoredAddressesMap["0x5892746dc50c211a397e38587c37a2c3c4f62a1d"] = false
	monitoredAddressesMap["0x5950a8a5ea5f071ac826ff5265e9190f754c73e3"] = false
	monitoredAddressesMap["0x5a9f97acae529b61e664bf24e2d63dd072ff9da0"] = false
	monitoredAddressesMap["0x5ae933bfbbaa04c3e05ae56295138174ada9799c"] = false
	monitoredAddressesMap["0x5c799fb67abf48cb534a7a68f05ee896a5c3800b"] = false
	monitoredAddressesMap["0x5f77fb1ba409569bd330c02d762d125716c6de8d"] = false
	monitoredAddressesMap["0x5a514ecd2220504b8d43de281723f2847f5ce80f"] = false
	monitoredAddressesMap["0x5e054654a9c682f3adf29a30263d30fd9b6ac7f4"] = false
	monitoredAddressesMap["0x5ff00d3836c515f3363c00fed1fc39be345c3d82"] = false
	monitoredAddressesMap["0x613365b3e73e30119b67de2961a68d608aea377c"] = false
	monitoredAddressesMap["0x618f8de3413e93cc631a69dea9fdbb49527af37e"] = false
	monitoredAddressesMap["0x6292d961b8b084c22ff2f28dcb223668b967a576"] = false
	monitoredAddressesMap["0x648bc2b0f68be949f93af9a04a586199eaed4f37"] = false
	monitoredAddressesMap["0x653cc58dd1ea31d6cd65a15554184e97c9fa5277"] = false
	monitoredAddressesMap["0x65c34104c1266d5499b9dbb3bfe0e68d5f50b00c"] = false
	monitoredAddressesMap["0x65f2dddf638c7a7118b22d610c9aeba141f2467f"] = false
	monitoredAddressesMap["0x666a32d58b86188ff5563b122c38793345251b9e"] = false
	monitoredAddressesMap["0x66cf045ddbcfd02cdc0ee347f744d728494217bd"] = false
	monitoredAddressesMap["0x6712d56ec56a811ed19a564ab5f96e4ce0b76527"] = false
	monitoredAddressesMap["0x69607ef7bffdfa21434bc8f6de55f07911576618"] = false
	monitoredAddressesMap["0x69689cdf0455bec07ac5feaa4180e30a5f7a8d9b"] = false
	monitoredAddressesMap["0x69dea231d61d47c974eaff7878ae1e1f0d292235"] = false
	monitoredAddressesMap["0x6ac362960f28e731813b694a6e0fdd524ce2e1e5"] = false
	monitoredAddressesMap["0x6ca59cf604a7873df78ef3f5ee8790f302a1f2a7"] = false
	monitoredAddressesMap["0x6d2f27149fbf6c559008e95ede61ff20f3e4b847"] = false
	monitoredAddressesMap["0x6eaa3825ed251c48b33011f260bca92aff24aeac"] = false
	monitoredAddressesMap["0x71539388e1fe647ef3e62486af0d9f0330d89692"] = false
	monitoredAddressesMap["0x72b10bc8188907431157849888ca95143b889bc6"] = false
	monitoredAddressesMap["0x72bd4a4454e135fec00a491b16d7236a2d5b8706"] = false
	monitoredAddressesMap["0x735cc07903c8f42c03d1101c494f7398be5ae0e7"] = false
	monitoredAddressesMap["0x73619c511d753e53753ca549d695eb0993d84726"] = false
	monitoredAddressesMap["0x73bdfa78eacb6c6801f4d5182aee9447e220be01"] = false
	monitoredAddressesMap["0x73b7424a32b34806f9ba10129843ce9cc3069397"] = false
	monitoredAddressesMap["0x75baa33eb5e887f6f6e337f5fb073ee68b9629b0"] = false
	monitoredAddressesMap["0x7601563e13cd42f557d2028201114fa6a44adf23"] = false
	monitoredAddressesMap["0x78273e3651c97979e6d7daad0f0585d6bb7e6303"] = false
	monitoredAddressesMap["0x79cce91857d98b72e1fb96ac6166a56e68c0c06b"] = false
	monitoredAddressesMap["0x7ab155f4dd53c345c67acf8bd9e610eb504e31c9"] = false
	monitoredAddressesMap["0x7f2507072b0970d978a50d6f643ec0d86982a0cc"] = false
	monitoredAddressesMap["0x7aa6e2506316f6d613277d4f2f4e4e1dc55e528e"] = false
	monitoredAddressesMap["0x7c1d6fc09594121a7e096126a077dd0bfb9923c9"] = false
	monitoredAddressesMap["0x7f9608ccbb245027fc4f3393f8b9e7bf38c46c50"] = false
	monitoredAddressesMap["0x807bcfb5c2fb614781016b63a6cb6672ba6660df"] = false
	monitoredAddressesMap["0x80d3a88549c2db69e324b0c079b4ac2ce54dbf94"] = false
	monitoredAddressesMap["0x8139ba933d84d73ad4be4a75853265c4fff01ce3"] = false
	monitoredAddressesMap["0x81b1dbb248a5fdc1521cc23306c83b2abbec53d1"] = false
	monitoredAddressesMap["0x83d58dc5add4534497f68d44ec2c405243f95544"] = false
	monitoredAddressesMap["0x83fbc98514197c1d547eacd417b4c3e6a11c8ba8"] = false
	monitoredAddressesMap["0x84a8fce7ec6d6ce29ba0bb4f59dce54dcd00174d"] = false
	monitoredAddressesMap["0x85717d25cc2867160546a89cdf99481698c3b51e"] = false
	monitoredAddressesMap["0x857c7803de6fc5e1f3fb0c5e13cf026e3976e590"] = false
	monitoredAddressesMap["0x86f07ee309655dbb0c169668f4e27848c0deda77"] = false
	monitoredAddressesMap["0x87484390a99aca31b1c9bff68c2457c74237847a"] = false
	monitoredAddressesMap["0x889557c0cab2cd6f013cbac9f95a41ade3b1c1f1"] = false
	monitoredAddressesMap["0x8961daa25a98a4c8ed84462e17d9ce6cd709aa55"] = false
	monitoredAddressesMap["0x8a2c35d88aea27e60db7e0dcd0cf52321ed64c18"] = false
	monitoredAddressesMap["0x8a2cf9aeb7633040d6ed23f84787647c912ecfee"] = false
	monitoredAddressesMap["0x8ae21e19d6c89328b36dc0b3131793ac75e996d9"] = false
	monitoredAddressesMap["0x8dc56ed3a0cc5c80f57ef86c213a57ee6e83666c"] = false
	monitoredAddressesMap["0x8e29228162a0accffd1e96904f8aa77ccb5e4335"] = false
	monitoredAddressesMap["0x8caadfb10e620108b6d0f65865a7cd4028d74536"] = false
	monitoredAddressesMap["0x8cca4b977347790d5f7319dadf81dfa3091668c2"] = false
	monitoredAddressesMap["0x9018a83534cd5a0ebad3e70710f6b6c248107105"] = false
	monitoredAddressesMap["0x91a96e0f7705a206b782a7d80dc92e0f7e53d927"] = false
	monitoredAddressesMap["0x91e1b7f779ae3839c61198757d24f37495acb6ee"] = false
	monitoredAddressesMap["0x91e9512663e9f1e9e83af82c809a1fad199a5978"] = false
	monitoredAddressesMap["0x9267abdc61a6c51a069766a910a79f51baad9d3e"] = false
	monitoredAddressesMap["0x94b3f35a7a3a24d791504f45bf2e137fa7a5486e"] = false
	monitoredAddressesMap["0x94e48a41d774bdebf72fa6947797d54ba20a7acd"] = false
	monitoredAddressesMap["0x94c78d10bce1fa43d17b392e7ee68d88a49ac60d"] = false
	monitoredAddressesMap["0x95fdffb33690407f5d4a943a8a725ece16ccea3b"] = false
	monitoredAddressesMap["0x974650493b2ada6d6ed7908aef585939a078b756"] = false
	monitoredAddressesMap["0x97da9af6345fd337bfb3ceaa0a46d03239fa304f"] = false
	monitoredAddressesMap["0x980cae4f2c7301d1d23fc709c379657c90d27d52"] = false
	monitoredAddressesMap["0x9aa3b504ca7948646147aa4150a356eb31d6e7bf"] = false
	monitoredAddressesMap["0x9c19b04669860dc557741e743bc07eea5d8fff69"] = false
	monitoredAddressesMap["0x9dfa3bab158f46af15553d86134165fca881a7e7"] = false
	monitoredAddressesMap["0x9e42c0225eb49fde6f6885c33d20577c879debd3"] = false
	monitoredAddressesMap["0x9e8f4f6a7b32eef43da3c8479038cffe7bc6e579"] = false
	monitoredAddressesMap["0x9fca8718e214c579228ca64672216195e9f7b02f"] = false
	monitoredAddressesMap["0x9c63fb7efee378027b91d4efb7c1f62762e073c2"] = false
	monitoredAddressesMap["0x9c81f882cf20d132c96f4acd7f6a2c27efd3309e"] = false
	monitoredAddressesMap["0x9d917df8dcacbeb66bda85b8c56895df5749cb52"] = false
	monitoredAddressesMap["0x9f831d9b6efd7d2bf51c6b0bd596d17f11dde013"] = false
	monitoredAddressesMap["0x9ff9c2611dccea9402fc0e297118fefa38af5cd4"] = false
	monitoredAddressesMap["0xa0d804e43ddc621fd183aef1a5560bd09ef692e5"] = false
	monitoredAddressesMap["0xa1c48d9400420ea49e82c0b7f7ea9cd673addc6b"] = false
	monitoredAddressesMap["0xa58affd719561f52625963d8774b0c2fbae071f2"] = false
	monitoredAddressesMap["0xaac4bd9c59c0e26e0d4f51f5b8d38d46aef4ec7e"] = false
	monitoredAddressesMap["0xabb05cc1c1874da687e34ddf69f3ee6fae1cef89"] = false
	monitoredAddressesMap["0xad18a7d263ad82c291030970adca2e2cc9d89e67"] = false
	monitoredAddressesMap["0xad440e6b26dd3a044a97294bf87c017d7fb81c67"] = false
	monitoredAddressesMap["0xaee203a6d904bfb6707223990bb268248ef972ae"] = false
	monitoredAddressesMap["0xb137d598a8d7a3b6291d10d4b1b5f41fd2ccbc34"] = false
	monitoredAddressesMap["0xb39f7c953209aad21d10f32dda30a815bd16aed9"] = false
	monitoredAddressesMap["0xb6dba64619f3a70bdd4ffde2e1f5281a0009f041"] = false
	monitoredAddressesMap["0xb8878cd00f51f088588602acb43c7008333e767e"] = false
	monitoredAddressesMap["0xb8ce310e46b13829c5c542a3cfa89f46e450f8ae"] = false
	monitoredAddressesMap["0xbb37ead38937b16b014227825a39c29a94b84848"] = false
	monitoredAddressesMap["0xbf57bd607d0785705b7a065dfe5f9be86e946bd5"] = false
	monitoredAddressesMap["0xc015260f3d8f13590a43d92e189fc31252574e07"] = false
	monitoredAddressesMap["0xc032f183d7c0dd0071265ad660ae96290431873e"] = false
	monitoredAddressesMap["0xc3960d2072c1c9d2136332137142d96ccbba1445"] = false
	monitoredAddressesMap["0xc5ff06991dbaf57bef6dd7a75056e62b7a2383fb"] = false
	monitoredAddressesMap["0xc8f1dfafb5caec6ed2714b6a0f9c803d4dec172e"] = false
	monitoredAddressesMap["0xc9d56287b414e1aa0963016aa721b527f095fd9c"] = false
	monitoredAddressesMap["0xcddba866a6b9ddd221848a7d29b582be3e6a00d8"] = false
	monitoredAddressesMap["0xd2db24b25307e1b03ef404e4b793d8f9ef2c4316"] = false
	monitoredAddressesMap["0xd697955b1715d11b0d10ce82396c00f28c1b2eba"] = false
	monitoredAddressesMap["0xd6ba445eadc80c7ba0f256e46ac959d7d109fb58"] = false
	monitoredAddressesMap["0xd7a7628dafa2ea4b8014167abc6196be72d30f0f"] = false
	monitoredAddressesMap["0xdd5ed75a9175b77685cfd27124f86b3a6c053660"] = false
	monitoredAddressesMap["0xddf3e4b40448ef7ea3de2e0958991956e4bb6e52"] = false
	monitoredAddressesMap["0xdfa01c48b6fd9276d35567469313059e2f3423b4"] = false
	monitoredAddressesMap["0xdb8785c60590012bfe3bb745b0a80d0a24504ea2"] = false
	monitoredAddressesMap["0xe52de9fb2e29bb8e1d9938a4c6daf243fbab2ac2"] = false
	monitoredAddressesMap["0xe6752641b59bffab5cce0e14dc517f9422acce12"] = false
	monitoredAddressesMap["0xe6a3d583db48bd8ae51c53c6ca717d7dde4c7f75"] = false
	monitoredAddressesMap["0xe7e00ff5133991a09dd6f91a8e9cd5e901ee18e1"] = false
	monitoredAddressesMap["0xe9c69e1f950b28a32524681827bec2641a5f693b"] = false
	monitoredAddressesMap["0xebf31e95d9709acfa18048b5686f9576aba6d63e"] = false
	monitoredAddressesMap["0xf43b43869dd95e53923b30a79902915c1faa47d3"] = false
	monitoredAddressesMap["0xf44072eda87ede9613b6ae1b812de8a60ade27a2"] = false
	monitoredAddressesMap["0xf534e9531231f8d70d09c97b1e6d8d475fc6caed"] = false
	monitoredAddressesMap["0xf6831fef8a943c0baf023ec5be4621dedc5df150"] = false
	monitoredAddressesMap["0xf9e1d0f54f557a183bd949d7664ea7c8aaaa8fd7"] = false
	monitoredAddressesMap["0xfba8039dbb9ab3a4bef0d69467bc9d7cc9c13b90"] = false
	monitoredAddressesMap["0xfaff5c7dc62a279909b25eddd9f40634dac9140c"] = false
	monitoredAddressesMap["0xfeb6a6abb0dd91b39273936a66eabef9b74617cc"] = false
	monitoredAddressesMap["0xa081c776c889936062f003bf145cb531956a59e1"] = false
	monitoredAddressesMap["0xa78d62ab83ad81b005e34457f6ec3367cd287d81"] = false
	monitoredAddressesMap["0xababeea381e891235ddb2ad5ca59c5d48360fe4f"] = false
	monitoredAddressesMap["0xae16202c161d22db810d0a5a0aad233373432895"] = false
	monitoredAddressesMap["0xb0e9697bccb637bca9832bb2e6d27242c96808ac"] = false
	monitoredAddressesMap["0xb15657374327eb26b7fbafdc7cc765130371d49b"] = false
	monitoredAddressesMap["0xb3b778007c914c705dfae1a6506869a95be9afdf"] = false
	monitoredAddressesMap["0xb476cbc60ad08e4a707c5aa4b3aebf7ea12bb054"] = false
	monitoredAddressesMap["0xb6f12c68542a3358abfac79e44df380c1e03b82c"] = false
	monitoredAddressesMap["0xb82651033562a0b797cd93148b7fe46fca910a26"] = false
	monitoredAddressesMap["0xb954f03876c46d3e9c8fb5c861ad5ed151ac9beb"] = false
	monitoredAddressesMap["0xbd463552cc313bfa2e7912f70c8ad7c5b7ab550e"] = false
	monitoredAddressesMap["0xbb798ec6b9e02b65c27314f0ded04626d278ff98"] = false
	monitoredAddressesMap["0xc1ceea569672598107a9378cebafc543fee60e3b"] = false
	monitoredAddressesMap["0xc1fd2a0fda4140bbe5817c4c1b2d80350b39397a"] = false
	monitoredAddressesMap["0xc7781081a25ebc4c59893319ac27aba05c481c51"] = false
	monitoredAddressesMap["0xc883e75ceba68dc6459443a6413d1ff7f8a355b7"] = false
	monitoredAddressesMap["0xcca702a7c8f9055b8b83cc5c6f9d0b09c15765cc"] = false
	monitoredAddressesMap["0xcebaa7b80e3f0f1b6fe8bdc4d3c628da8ef330fa"] = false
	monitoredAddressesMap["0xd2ea382e498316d91b9de8557670149b479721a0"] = false
	monitoredAddressesMap["0xd445f61ebca3d6b4c57eef1f39fdab6595ef8972"] = false
	monitoredAddressesMap["0xd51a47e2c1e105bb2d2b658766bae5ebf86fc8c4"] = false
	monitoredAddressesMap["0xd53955fa72ae2844f9add18bb455898af8e470f1"] = false
	monitoredAddressesMap["0xd5aefbf0038a6cda8615699bc6092d26d46c2b27"] = false
	monitoredAddressesMap["0xd815bbdb973fcfae73f27ddc9a135e377028c1c5"] = false
	monitoredAddressesMap["0xd94531278c53bbbb3cc716f9e198b1fdccc50315"] = false
	monitoredAddressesMap["0xdee1645558e3b8f8f20e186acd5e8a7699127f30"] = false
	monitoredAddressesMap["0xdbcc2e02defcf97afa83a42ae9b66596c0f1f5d1"] = false
	monitoredAddressesMap["0xe0fda40ed2db6505c7d9b47249ef869031ae84cb"] = false
	monitoredAddressesMap["0xe4f62ae333713e8f782bd83f9fb6867c48d092c8"] = false
	monitoredAddressesMap["0xe6502a7faf3187b64ee772f733aa8b2de5e159f9"] = false
	monitoredAddressesMap["0xe755445d9ae759292262342586b90a48a44411a6"] = false
	monitoredAddressesMap["0xefb571efd5602e8a521342b15e7cf93bb99a9694"] = false
	monitoredAddressesMap["0xedba536cc155bb7d7ca41b696254184ef210822b"] = false
	monitoredAddressesMap["0xf22b9431279708fd7d18e979291e356189de7f94"] = false
	monitoredAddressesMap["0xf29439c52819ff9e352eceb89165f4ad7226f21b"] = false
	monitoredAddressesMap["0xf2982a81f0b9e40dd5e040c8aabf6aa7d9ef5092"] = false
	monitoredAddressesMap["0xf4cb3f94d79baec15087f6aabf5d1375ffa25b9f"] = false
	monitoredAddressesMap["0xf5da24cca079de78d678d47457bc6a443fd44097"] = false
	monitoredAddressesMap["0xf6869bbaa72ef6ca160cb09a92c4a83f9b8a3c3c"] = false
	monitoredAddressesMap["0xf8ce91853c0b3756f2b9e79f4f0aaa034ca70643"] = false
	monitoredAddressesMap["0xfb0db40592df60b4b994e89cfaf00b68150fc43d"] = false
	monitoredAddressesMap["0xfc6558d4ec528dc6be1cd49729974942f7cf4dde"] = false
	monitoredAddressesMap["0xfcff15d3f81b57cce122539ddf8d859c8c844c71"] = false
	monitoredAddressesMap["0xfe423f6b9b3aa093cc08831d9b106027f97e132e"] = false
	monitoredAddressesMap["0x00000066b4cecc3965d776fef323c30788ba397b"] = false
	monitoredAddressesMap["0x00000c9eab290533cd31ae5d3b44fbc48b335ab3"] = false
	monitoredAddressesMap["0x0000106e912ae7bb1e72e9d8ff76f6252376a60e"] = false
	monitoredAddressesMap["0x0000265868335a145c58a3fb25ec5400ab5b8bd2"] = false
	monitoredAddressesMap["0x000029c8bf6f0790f2bbc8afee6726e2b554a58e"] = false
	monitoredAddressesMap["0x000033476ea7769ad1078fedf92910086fd9c390"] = false
	monitoredAddressesMap["0x00003e132a49a9c0f066ce2fe2ab48b886b340cf"] = false
	monitoredAddressesMap["0x00005bcf61d3c8fe4928e6c9ed5a9bd2263d6de7"] = false
	monitoredAddressesMap["0x00005cfe2c802880c2a0aa89b6296a3607ab9c6b"] = false
	monitoredAddressesMap["0x00007c3325b084b979b622ddf264bf9e45b8c2fd"] = false
	monitoredAddressesMap["0x0000f7f39325076881e5fc566e99595542532ae2"] = false
	monitoredAddressesMap["0x0000baa8f700af2476492b19e378d61b90454982"] = false
	monitoredAddressesMap["0x0003afa6dd16a9c9cdec9615c8f689bd11783e7d"] = false
	monitoredAddressesMap["0x0030725b6b4f71779232e8dc1f52084022dfa45e"] = false
	monitoredAddressesMap["0x003449904a67b30ffc114e0b844c04f0a0343240"] = false
	monitoredAddressesMap["0x0044a537a1d5b55c82e487f7d120872699274c97"] = false
	monitoredAddressesMap["0x007279f614693de87fd16f9b73f9672b8003264f"] = false
	monitoredAddressesMap["0x007b1b23fd76494d161648059f95a512b93cafe1"] = false
	monitoredAddressesMap["0x008e03a25c13f440cff9f51b3ef3200e8ec20f91"] = false
	monitoredAddressesMap["0x009b30b999c85058dcd342d7548729bcccb16b4c"] = false
	monitoredAddressesMap["0x00bd1f96df54abe78d34fba23f2f4a5190c0e0b6"] = false
	monitoredAddressesMap["0x00da7ac131fad2c45a3906d985da3bdd6b96e8ee"] = false
	monitoredAddressesMap["0x00a326d14ac270142b8902139b8589b84cfd1fbc"] = false
	monitoredAddressesMap["0x00a4394886dfb187ce7de90072475b8be58a95c1"] = false
	monitoredAddressesMap["0x00b85054903ed866cdb1c0799286323bb789d448"] = false
	monitoredAddressesMap["0x090a69f59556eeef5076f1a33d59c732c92bb2e1"] = false
	monitoredAddressesMap["0x0b06c8341a422b77acdd427c6f01fe85f483aec7"] = false
	monitoredAddressesMap["0x0d0a0de94229f80f9d3732694f1f6d571fedd2e6"] = false
	monitoredAddressesMap["0x0c4d96a1c5708661688b85bdc37d0b7a8da9fc89"] = false
	monitoredAddressesMap["0x10de343596915b4ae0b5ba18c8452a4be45f6993"] = false
	monitoredAddressesMap["0x12a5b0b910fa573920fc1f786e37a2759e9ba06f"] = false
	monitoredAddressesMap["0x13303476fec8d6a06ce236d7bada4e359dbeca11"] = false
	monitoredAddressesMap["0x15064f5f4563c9288b75593a7a6e00a566a41ba5"] = false
	monitoredAddressesMap["0x153561297d76253ec0a77d5e053cd0d0679b81b4"] = false
	monitoredAddressesMap["0x15446dde5c56b11e92d81012c79c12d2b4d1af10"] = false
	monitoredAddressesMap["0x175514606b8a83a64f7c2e4c01bb4f3efa7d0bf7"] = false
	monitoredAddressesMap["0x1db4d24f48b3cced0cd29591265e78e19952c6b6"] = false
	monitoredAddressesMap["0x1c32f807e4c2b170431f254ffa3c63eb99fa565b"] = false
	monitoredAddressesMap["0x242daf62dc3abc87c36aea0b593d223f919e918f"] = false
	monitoredAddressesMap["0x2598f6b88d9f82152f1bbe551132bd7e2aa953e0"] = false
	monitoredAddressesMap["0x29baf3e6aca05316613f91f56e3f3b6c76bc3846"] = false
	monitoredAddressesMap["0x29e990000000f72253e0f4a4df9c8319c018a2b3"] = false
	monitoredAddressesMap["0x2a1e8d0d3aa31a444566e4f0a770b4126106e05d"] = false
	monitoredAddressesMap["0x2d8167772f7191afd9bdbda97b39f7db9d025bb6"] = false
	monitoredAddressesMap["0x2f42c38fe566de4c256056d95bf19d1f91346b64"] = false
	monitoredAddressesMap["0x305b147302d5d18f04c5299995c83709022e93fa"] = false
	monitoredAddressesMap["0x357ee72591a310d8eaae8b2c0d7fe36b3a7accf1"] = false
	monitoredAddressesMap["0x36f743e1cc4c0d153474af3936f35166dfdae8fe"] = false
	monitoredAddressesMap["0x37243443f3440480c2121d0d4ab13adcec6330cc"] = false
	monitoredAddressesMap["0x37c94758e3a3cb5285f668b0eda3b767a537a878"] = false
	monitoredAddressesMap["0x389597229c47e131cf5dd8f5f9457cc26c834738"] = false
	monitoredAddressesMap["0x3bd189a9b1c11684b08f6464866dfa431362a06e"] = false
	monitoredAddressesMap["0x3f064079860b72446f846605592d644c74dbd588"] = false
	monitoredAddressesMap["0x3fcd8998462564603c3ac6ffabc16295caa43888"] = false
	monitoredAddressesMap["0x402b28bbfadebf78ec2d4e12ce5a6ec6f885f811"] = false
	monitoredAddressesMap["0x40c49a43b8d5f4e43eb46d02f06b96facedc309a"] = false
	monitoredAddressesMap["0x40c926d8953dadd98c3b201c6da908d09b96aced"] = false
	monitoredAddressesMap["0x41880a6c0bf00b0c159a8154d66b676a995d2383"] = false
	monitoredAddressesMap["0x41f0955c599fe389ce0d8e49b99914dcf34d2056"] = false
	monitoredAddressesMap["0x437b4d05704c3af1fed4b6cc2d17a1cac0a06135"] = false
	monitoredAddressesMap["0x43ec5e707f47695509c46e59296f47f1142b5f84"] = false
	monitoredAddressesMap["0x44e05b25115fb86f0e9861cea0bf27e50f2338bf"] = false
	monitoredAddressesMap["0x44dba507b909a6f92f3a708a844d4c4f23622bee"] = false
	monitoredAddressesMap["0x46b6446fd49c9ac17d21ee4ccd8ee2f700089caf"] = false
	monitoredAddressesMap["0x47d2eb347e19fbd0e61d2fa39f490f538e2e35e9"] = false
	monitoredAddressesMap["0x4a6639b10ef0613c0db5c8256f30fef82728928a"] = false
	monitoredAddressesMap["0x4b0d6f4f2bf62a6ae0143e70deea894922ff5e19"] = false
	monitoredAddressesMap["0x4e485fcfa48082082aeb80d812c70ba07126c8be"] = false
	monitoredAddressesMap["0x4fcc2ff6c75923d33b4f5af4c524461014b2ee1c"] = false
	monitoredAddressesMap["0x5207f0d9c61df7c19e25960f0d786aaaaea23748"] = false
	monitoredAddressesMap["0x52c668bbc8cb3df004f5d1c0342efeba7c4813f4"] = false
	monitoredAddressesMap["0x55ae3f67039c332f55be00c1d33d989d2da108c5"] = false
	monitoredAddressesMap["0x5a289646bfb958c3158a33b1e4b8a8c254b3b5aa"] = false
	monitoredAddressesMap["0x5acd6beda8fc494240713c00965644f3dd2e934e"] = false
	monitoredAddressesMap["0x606646a67f59294c6f37a29394d192fbcfba918f"] = false
	monitoredAddressesMap["0x62011ecdcf84ef21ccbbc03c487601633bec4f72"] = false
	monitoredAddressesMap["0x646f8b2f3850a2aa3c8e365d6f5d069ec8edb048"] = false
	monitoredAddressesMap["0x665c153cd9ed58d004842111dda898d6383e037a"] = false
	monitoredAddressesMap["0x6689b3735fc56e5594864ee190feadd956fca7d2"] = false
	monitoredAddressesMap["0x66de19f1bd76194ccc857f0784993a8ba6a69376"] = false
	monitoredAddressesMap["0x6768adeb58664959a56614d5ba02c1bbab57412f"] = false
	monitoredAddressesMap["0x67d1f31eeef182cfb40c0719a8c0000fa7ddcaa9"] = false
	monitoredAddressesMap["0x68f81275f1526a9fcbd9eff330fb7bf339cb45d5"] = false
	monitoredAddressesMap["0x6becab24ed88ec13d0a18f20e7dc5e4d5b146542"] = false
	monitoredAddressesMap["0x6df313c77a9eb37f4df38ad421b950b0ca35ece9"] = false
	monitoredAddressesMap["0x6f892542cd8e1b85d13d7f3c93a1f14612111738"] = false
	monitoredAddressesMap["0x6a2049780b0b8859872e0c0ea3a8921f57b5e095"] = false
	monitoredAddressesMap["0x6e422be1845a91c9be36baf6edfb551533c8c6e9"] = false
	monitoredAddressesMap["0x6f9f050aca780530260aaa51ecd7e18f95d242de"] = false
	monitoredAddressesMap["0x70033cad2e83ca6a716a7c86fd2238c70b0547dd"] = false
	monitoredAddressesMap["0x76d9161df0ceaeec45974dbeb7bd836ac92e6f6b"] = false
	monitoredAddressesMap["0x777a1e3f589137618bb572bf54ce8e7d2746700e"] = false
	monitoredAddressesMap["0x79a478a779e9417192f7e09e2fdae4bbc03ba56a"] = false
	monitoredAddressesMap["0x7e77777772d74cba60638f3c19c60a3387172a06"] = false
	monitoredAddressesMap["0x7a1f5a5afbbc831f5025e39c93b3a35ba1aaefb9"] = false
	monitoredAddressesMap["0x80be28fc7c2203a69e6a8c393364241ff246677b"] = false
	monitoredAddressesMap["0x82519ff9c5b6c87acd521de62951be0239aacaba"] = false
	monitoredAddressesMap["0x8501398adfd5ca45567051dbe47b29a31d74e8cb"] = false
	monitoredAddressesMap["0x871aa01b740d841e8f4f0e85da85a12ce331cf8a"] = false
	monitoredAddressesMap["0x8755a7734dbf30d47344ce119cc3e3fe2af74bb4"] = false
	monitoredAddressesMap["0x8a8e42d12ca1f7de4a74f10066f231f78c362adf"] = false
	monitoredAddressesMap["0x8b970c0911cb316e467d214d8cd2b9acb1239f75"] = false
	monitoredAddressesMap["0x905451008d2d6510fc4ef008ad91c2340824ffc2"] = false
	monitoredAddressesMap["0x918453d249a22b6a8535c81e21f7530cd6ab59f1"] = false
	monitoredAddressesMap["0x93f529d5f3001ae7d6319e5458fe72066df763df"] = false
	monitoredAddressesMap["0x9502c292823a3aa5497fed15638c6aa71621b315"] = false
	monitoredAddressesMap["0x97ab1b8a3addd0b82c3375da9b4bf6a12950f802"] = false
	monitoredAddressesMap["0x9fda5c28131f25eee716c9bb9e3abf09173f965a"] = false
	monitoredAddressesMap["0x9df16c3fcb750c7f32075536aa21bc770605bced"] = false
	monitoredAddressesMap["0xa045e11fb1551d7196b5b0526431688efd49cfea"] = false
	monitoredAddressesMap["0xa5110fd6cba408a6b2352b25e5564e7d0c777fa6"] = false
	monitoredAddressesMap["0xa531704e881f797b524f87d3ab737e592ed11d68"] = false
	monitoredAddressesMap["0xa76ebe12c2ff4401da3eddc25226baa42ee92c65"] = false
	monitoredAddressesMap["0xaaaaa6a1700fde06541f740b8c2b208f28bf86c2"] = false
	monitoredAddressesMap["0xaa24325b9d108492fb5d8b8583e1705986d70e04"] = false
	monitoredAddressesMap["0xaf4b59e535df18942241f06a4eb9bcb32f45f43c"] = false
	monitoredAddressesMap["0xb367ddb3a33278d1b3fc6741e01293bac4949072"] = false
	monitoredAddressesMap["0xbc69ecc478d4c1722a7151e43e2a78ccd0d5d5fb"] = false
	monitoredAddressesMap["0xc0262ee6b085d652ad5c4bfdee03569b8c3ba50f"] = false
	monitoredAddressesMap["0xc1e088d3c95579254ca204c7470eb31f6053f16b"] = false
	monitoredAddressesMap["0xc27a83e26031fe0870c85a1a73b30d337a14e4b4"] = false
	monitoredAddressesMap["0xc533a4e3350deecaa0bf0fcba92d4a6138013b18"] = false
	monitoredAddressesMap["0xc921157e47e5a73629e266e7e27e73b2270b09b6"] = false
	monitoredAddressesMap["0xcab5e39af48be66fb04703ca41c5eccc2584d23e"] = false
	monitoredAddressesMap["0xcc4a5831dd286b3de8820f4d562eccc4af635b43"] = false
	monitoredAddressesMap["0xcf4212623cc5f81025e5af515cfad847f922bc90"] = false
	monitoredAddressesMap["0xd0ac67e5b837899813c0ae05d4f17e29a451a928"] = false
	monitoredAddressesMap["0xd7019b95f4795eb3b7558f8cadf1524781a23e80"] = false
	monitoredAddressesMap["0xdb5cca8ca41d5e21a2d317be10f84cd3bb65ea1c"] = false
	monitoredAddressesMap["0xdb7cd62c2350b7dee1fe336f2a2941af4dccf055"] = false
	monitoredAddressesMap["0xdd5e4dbcff073a5f12adb90e156db5ea96557982"] = false
	monitoredAddressesMap["0xe03793e63776cf69fe42414ed03bb924d4d9157e"] = false
	monitoredAddressesMap["0xf3a3fd06a875a09d7cd5fd18fdbe22493fc86abd"] = false
	monitoredAddressesMap["0xf7e4018be0be8d350d4ea46840965399a6cd93a5"] = false
	monitoredAddressesMap["0xf95fdc05714ebb786e5f5bc14aae430375390b65"] = false
	monitoredAddressesMap["0xf966b95e3261d604f77a2ad9af75a4e14055e548"] = false
	monitoredAddressesMap["0xfedbfaf9e4554520fbbe448638d9645942599eac"] = false
	monitoredAddressesMap["0xa065c23f48ae275c376eabc09b9b9b4557e57c14"] = false
	monitoredAddressesMap["0xa4619ef284d95d0656bdada7b49afc34614f3518"] = false
	monitoredAddressesMap["0xa6c558bb862861994fef89f02cf0ab5654c16ffe"] = false
	monitoredAddressesMap["0xb01c5685a506f971e2de0c33e853d3b50eed3f81"] = false
	monitoredAddressesMap["0xb1ecadf336c686fc66e692d56837c1eee92091b5"] = false
	monitoredAddressesMap["0xb3707d5a03660f5319ddc4865c8ad2cee15b9a23"] = false
	monitoredAddressesMap["0xb3bd6aaac41efd58adc9a6b3b867a16316d13bc6"] = false
	monitoredAddressesMap["0xb80df84da00c88173908410e375dd7e7bb58552f"] = false
	monitoredAddressesMap["0xba7b55eb7c35797b5872469e77ee11982cd1299d"] = false
	monitoredAddressesMap["0xbb3a8c227bfbcb0ff70802dee83246b507c57dcb"] = false
	monitoredAddressesMap["0xbdc25340d3450a364156e5851ac9fb83b115486d"] = false
	monitoredAddressesMap["0xba8d01980185406d7c35e9f162c82c17ec3eada9"] = false
	monitoredAddressesMap["0xc7c8da3cb9eeaf3ef5ca6476f0be99be85748618"] = false
	monitoredAddressesMap["0xccd7bdff63017081b5cf72993d5d84cf2a266330"] = false
	monitoredAddressesMap["0xd4d470b3a938c1bad0a40fc046dfe1993c3f1f46"] = false
	monitoredAddressesMap["0xd4fbc28dc6e196a5e088e917aec77983145b0a84"] = false
	monitoredAddressesMap["0xde3054b267dfff0317259bc6e69bd0b03042aec6"] = false
	monitoredAddressesMap["0xde92bf7944f0258865b9a52c38983e2456cc16b6"] = false
	monitoredAddressesMap["0xe0fca959877f8e328da4694c7833ea4831b828ab"] = false
	monitoredAddressesMap["0xe43351bd6cdf6cb64b1dfde1464e98a0c403b631"] = false
	monitoredAddressesMap["0xe84bf35e0d76390bceaf051d5fe6e0faa85f2f44"] = false
	monitoredAddressesMap["0xee634c2b0553aa8e123595c5b6b70a42bdcb5ca1"] = false
	monitoredAddressesMap["0xf13ecd2c3b4e7c360ec996197699c8ea8e8f903c"] = false
	monitoredAddressesMap["0xf142f26d1cac4ba8a6e6d7974d243eda2fe5f4f9"] = false
	monitoredAddressesMap["0xf2f7d4b9e10c3d871da5f8002350a34981bfcf33"] = false
	monitoredAddressesMap["0xf5940c053b878856410c8df0bbcb47dbf2d8e4a0"] = false
	monitoredAddressesMap["0xf666666666e8025c503209ac580a5aa4b39a090c"] = false
	monitoredAddressesMap["0xf7bc9f625d9b386cbe8740184761cf85b0db53c7"] = false
	monitoredAddressesMap["0xfd8ae36fe93d8b7261e58b5a3439fa451a553ec6"] = false
	monitoredAddressesMap["0xfdbf9365b39567b5570f4083286c2cf72c4641f0"] = false
	monitoredAddressesMap["0xfe3ce7bc94861c2ad6140c59718f87703134937e"] = false
	monitoredAddressesMap["0x43211ffc4db5dbd9adb3af3af87b585dd0f77c8f"] = false
	monitoredAddressesMap["0x43211ffc4db5dbd9adb3af3af87b585dd0f77c8f"] = false
	monitoredAddressesMap["0x4fcc2ff6c75923d33b4f5af4c524461014b2ee1c"] = false
	monitoredAddressesMap["0x67d1f31eeef182cfb40c0719a8c0000fa7ddcaa9"] = false
	monitoredAddressesMap["0x49c915780c4fFAa3C731f7265a51589C17ac6DD8"] = false
	monitoredAddressesMap["0xaB4719c60e732a1fe7cE8C7e250C14d746aD6FF9"] = false
	monitoredAddressesMap["0x867E29A4Dd0d5cA0e23eeacD2146dF164804c63f"] = false
	monitoredAddressesMap["0xC9D81352fBdb0294b091e51d774A0652ef776D99"] = false
	monitoredAddressesMap["0x885B09500cbc1C9cbcD0626459385f471eF72d47"] = false
	monitoredAddressesMap["0x63148E9B9090D0D676533d5f9B6f8aB1f3739abd"] = false
	monitoredAddressesMap["0x9b871F717B3cdc42F4FCf9153ec81B6C46258Be4"] = false
	monitoredAddressesMap["0x2bF90726636273b910AB0eA72cc3A2598AeBF1f2"] = false
	monitoredAddressesMap["0x505292C3B1027F87821f6Ce9e7A77F3Ae8df4ED7"] = false
	monitoredAddressesMap["0x67d1f31eeEF182cFB40c0719A8c0000fA7DDCAA9"] = false
	monitoredAddressesMap["0x674933d412d047004e5c9B6F50A068F273f71c91"] = false
	monitoredAddressesMap["0x745381F29Dcaa144142B2048D7555Ddd1205b784"] = false
	monitoredAddressesMap["0x9Ff7864Fe1aFbEd6a75F66f796f10300F8A466b0"] = false
	monitoredAddressesMap["0x9e59bd53F388f68a469b35B4a5b184070418e97A"] = false
	monitoredAddressesMap["0xB1732709a33D853689aCE9e3236a0d762497AC1e"] = false
	monitoredAddressesMap["0xAa5Dd1aC6E16e5F34C88bb7b3d67938d22EBe9a9"] = false
	monitoredAddressesMap["0xe84Fd91CBbA2FcDDc22D96965158ae676Dd61D28"] = false
	monitoredAddressesMap["0xC1A065a2d29995692735c82d228B63Df1732030E"] = false
	monitoredAddressesMap["0x39eBDcF011D4ED511B4d6F77B0bd592c9635bed7"] = false
	monitoredAddressesMap["0x23b2Bcae8dEc395afD931f49Ea8387937e515cA1"] = false
	monitoredAddressesMap["0x05BeA250f2d1e288AFe9f1eeb5BaA5d0Ba5A3Ca3"] = false
	monitoredAddressesMap["0x1f6E8BA65F9263E8EAC63d7a76407E5982bBec83"] = false
	monitoredAddressesMap["0x9D8106B27DEa28702Ad46e8e06cfb3095ea65647"] = false
	monitoredAddressesMap["0x54133617Ad48aCf04E583170d08C1a77f95F11eA"] = false
	monitoredAddressesMap["0x6D91F54040D517e2DA18afF74f1a6ecD087B839D"] = false
	monitoredAddressesMap["0x0E8f54FAeE779D8de47EcD94a2944Eedd1d7Da92"] = false
	monitoredAddressesMap["0x4c62c824e4b77138eDe01437e808c57743d63e59"] = false
	monitoredAddressesMap["0xc87aDa508d705a2AFAC03E5A5996ccB0759183E8"] = false
	monitoredAddressesMap["0xEe135e815A2c71F02E21DF45B1dE57E1CaFa39fe"] = false
	monitoredAddressesMap["0x596B473CFe5746F35D601A588707c7236590D00b"] = false
	monitoredAddressesMap["0x7ec23cd77626D9f8318FBB8460d6eb5b115aEB9E"] = false
	monitoredAddressesMap["0x757d6843A8177821cbf05Da50156Aa28a0f83A6b"] = false
	monitoredAddressesMap["0xD11015e37F4eFb7ECB8E461B3A2AcB22703dbf92"] = false
	monitoredAddressesMap["0xeaa8Ab6B7B5D2e7987bbdB494a9647DFb860620A"] = false
	monitoredAddressesMap["0x8dA4f36e90e7be8379348f3637D54efA2aaD070C"] = false
	monitoredAddressesMap["0x32F4c2dF50F678a94609e98f8Ee7fFb14B6799bc"] = false
	monitoredAddressesMap["0x218F04bCE746C068ECe0b0b88f9E9DfD9dDA6fdb"] = false
	monitoredAddressesMap["0xC30FF49429b3077fc2B9A910B072F2300dC41B9A"] = false
	monitoredAddressesMap["0x5A27374a543103beAb2d0001BB2C17d3eaEAb9C8"] = false
	monitoredAddressesMap["0xC5Cfc3BA611BDe7E48dF46D1f3063bd57c2C34a8"] = false
	monitoredAddressesMap["0x0A40992be4Cc0c77A0C599C9FD072fCFD9bc914A"] = false
	monitoredAddressesMap["0xD558c4799D16334E9cC27110A5E402E88bE70028"] = false
	monitoredAddressesMap["0x47169f78750Be1e6ec2DEb2974458ac4F8751714"] = false
	monitoredAddressesMap["0x5E6B83F6A4367a01036dB93e0F6c9F9D82f46106"] = false
	monitoredAddressesMap["0x90345922508830e97be01CB07e0364270f9F0B2D"] = false
	monitoredAddressesMap["0x2e17Ed18587610B16Bf822E76dd0d07DD6b336E6"] = false
	monitoredAddressesMap["0xCef9e356049f4e1fA02A26498AA14D7af740CcFD"] = false
}
