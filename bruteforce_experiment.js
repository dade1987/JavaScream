tring.prototype.replaceAt = function (index, replacement) {
    return this.substring(0, index) + replacement + this.substring(index + replacement.length);
}

//https://github.com/jaalto/external-sf--crunch-wordlist/blob/master/charset.lst

let password = 'AA0000000000'

let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
let nums = '0123456789'

for (let i0 = 0; i0 < chars.length; i0++) {
    password = password.replaceAt(0, chars[i0])
    for (let i1 = 0; i1 < chars.length; i1++) {
        password = password.replaceAt(1, chars[i1])

        for (let i2 = 0; i2 < nums.length; i2++) {
            password = password.replaceAt(2, nums[i2])
            for (let i3 = 0; i3 < nums.length; i3++) {
                password = password.replaceAt(3, nums[i3])
                for (let i4 = 0; i4 < nums.length; i4++) {
                    password = password.replaceAt(4, nums[i4])
                    for (let i5 = 0; i5 < nums.length; i5++) {
                        password = password.replaceAt(5, nums[i5])
                        for (let i6 = 0; i6 < nums.length; i6++) {
                            password = password.replaceAt(6, nums[i6])
                            for (let i7 = 0; i7 < nums.length; i7++) {
                                password = password.replaceAt(7, nums[i7])
                                for (let i8 = 0; i8 < nums.length; i8++) {
                                    password = password.replaceAt(8, nums[i8])
                                    for (let i9 = 0; i9 < nums.length; i9++) {
                                        password = password.replaceAt(9, nums[i9])
                                        for (let i10 = 0; i10 < nums.length; i10++) {
                                            password = password.replaceAt(10, nums[i10])
                                            for (let i11 = 0; i11 < nums.length; i11++) {
                                                password = password.replaceAt(11, nums[i11])

                                                console.log(password)


                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}                              