package ssl.expiration.detector

import spock.lang.Specification
import spock.lang.Unroll

class ValidatorTest extends Specification {
    @Unroll
    def "Smoke"() {
        when:
        Validator obj = new Validator();
        boolean ret = obj.exec(url)

        then:
        ret == true

        where:
        url                         | _
//        "https://studio.design/" | _
        "https://3tomeno.work" | _
        "https://offer1201.com"     | _

    }
}
